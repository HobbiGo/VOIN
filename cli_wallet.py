import json
import os
from typing import Any, Dict, Optional

import requests
from eth_account import Account
from eth_account.messages import encode_defunct
from security.pqc_signer import sign as pqc_sign
from voin import canonical_tx_message


def normalize_signature(sig: Any) -> str:
    """Menormalkan tanda tangan ke string hex berawalan 0x."""
    if isinstance(sig, bytes):
        hex_str = sig.hex()
    else:
        hex_str = str(sig).strip()
        if hex_str.startswith(("0x", "0X")):
            hex_str = hex_str[2:]
    return f"0x{hex_str}"


def build_signed_tx_payload(
    sender_sk_evm: str,
    sender_sk_pqc: Any,
    recipient: str,
    amount: int | str,
    nonce: int,
    validator_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Membuat transaksi kanonis dan menandatanganinya dengan ECDSA + PQC."""
    if not sender_sk_evm or not sender_sk_evm.strip():
        raise ValueError("sender_sk_evm tidak boleh kosong.")
    if not recipient or not recipient.strip():
        raise ValueError("recipient tidak boleh kosong.")
    if nonce < 0:
        raise ValueError("nonce tidak boleh negatif.")

    sender_acct = Account.from_key(sender_sk_evm.strip())
    tx: Dict[str, Any] = {
        "sender": sender_acct.address,
        "recipient": recipient.strip(),
        "amount": amount,
        "nonce": nonce,
    }

    msg = canonical_tx_message(tx)
    if isinstance(msg, str):
        msg_bytes = msg.encode("utf-8")
    elif isinstance(msg, (bytes, bytearray)):
        msg_bytes = bytes(msg)
    else:
        msg_bytes = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode("utf-8")

    ecdsa_sig_raw = sender_acct.sign_message(encode_defunct(primitive=msg_bytes)).signature
    pqc_sig_raw = pqc_sign(msg_bytes, sender_sk_pqc)

    payload: Dict[str, Any] = {
        "tx": tx,
        "sig_ecdsa": normalize_signature(ecdsa_sig_raw),
        "sig_mldsa": normalize_signature(pqc_sig_raw),
    }

    if validator_id and validator_id.strip():
        payload["validator_id"] = validator_id.strip()

    return payload


def send_voin(
    node_url: str,
    sender_sk_evm: str,
    sender_sk_pqc: Any,
    recipient: str,
    amount: int | str,
    nonce: int,
    validator_id: Optional[str] = None,
    api_token: Optional[str] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    """Mengirim transaksi hybrid (ECDSA + PQC) ke endpoint /transaction pada node/gateway."""
    base_url = (node_url or "").strip().rstrip("/")
    if not base_url:
        raise ValueError("node_url tidak boleh kosong.")

    payload = build_signed_tx_payload(
        sender_sk_evm=sender_sk_evm,
        sender_sk_pqc=sender_sk_pqc,
        recipient=recipient,
        amount=amount,
        nonce=nonce,
        validator_id=validator_id,
    )

    headers: Dict[str, str] = {"Content-Type": "application/json"}
    token = (api_token or os.getenv("API_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-API-Token"] = token

    endpoint = f"{base_url}/transaction"
    print(f"Mengirim transaksi {amount} VOIN ke {recipient} melalui {endpoint}...")

    try:
        response = requests.post(endpoint, json=payload, headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        error_result = {"ok": False, "error": f"Koneksi gagal: {exc}"}
        print(f"Error: {error_result['error']}")
        return error_result

    try:
        body: Any = response.json()
    except ValueError:
        body = {"raw_text": response.text}

    result: Dict[str, Any] = {
        "ok": 200 <= response.status_code < 300,
        "status_code": response.status_code,
        "response": body,
    }

    print(f"Status: {response.status_code}")
    print(f"Respons: {json.dumps(body, indent=2, ensure_ascii=False) if isinstance(body, dict) else body}")
    return result


if __name__ == "__main__":
    default_node_url = (
        os.getenv("VOIN_NODE_URL")
        or os.getenv("VOIN_GATEWAY_URL")
        or "http://127.0.0.1:5000"
    )
    print("Kerangka CLI Wallet VOIN siap digunakan.")
    print(f"Default Node/Gateway URL: {default_node_url}")
    print("Atur VOIN_NODE_URL / VOIN_GATEWAY_URL dan panggil send_voin(...) untuk mengirim transaksi.")
