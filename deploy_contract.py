import os
import requests
from eth_account import Account
from eth_account.messages import encode_defunct
from security.pqc_signer import generate_keypair, sign as pqc_sign
from voin import canonical_tx_message

NODE_URL = os.getenv("VOIN_NODE_URL", "http://127.0.0.1:5000")
CONTRACT_ADDRESS = "0xVOIN_Web4_Messenger_Contract"


def create_alice_account():
    """Membuat akun ECDSA dan pasangan kunci ML-DSA untuk skenario uji coba."""
    ecdsa_account = Account.create()
    pk_mldsa, sk_mldsa = generate_keypair()
    return ecdsa_account, pk_mldsa, sk_mldsa


def register_alice_keys(node_url: str, ecdsa_account, pk_mldsa: bytes):
    """Mendaftarkan kunci publik ECDSA dan ML-DSA milik Alice ke node."""
    payload = {
        "address": ecdsa_account.address,
        "pk_ecdsa": ecdsa_account.address,
        "pk_mldsa": pk_mldsa.hex(),
    }
    response = requests.post(f"{node_url}/register_key", json=payload, timeout=15)
    response.raise_for_status()
    return response.json()


def build_signed_tx(ecdsa_account, sk_mldsa: bytes, recipient: str, amount: int, nonce: int, data_payload: dict) -> dict:
    """Membentuk transaksi kanonis dan menandatanganinya dengan ECDSA serta ML-DSA."""
    tx = {
        "sender": ecdsa_account.address,
        "recipient": recipient,
        "amount": amount,
        "nonce": nonce,
        "data": data_payload,
    }
    msg = canonical_tx_message(tx)
    sig_ecdsa = ecdsa_account.sign_message(encode_defunct(primitive=msg)).signature.hex()
    sig_mldsa = pqc_sign(msg, sk_mldsa).hex()

    tx["sig_ecdsa"] = sig_ecdsa
    tx["sig_mldsa"] = sig_mldsa
    return tx


def send_tx(node_url: str, tx: dict):
    """Mengirim transaksi yang sudah ditandatangani ke endpoint /transaction."""
    response = requests.post(f"{node_url}/transaction", json=tx, timeout=15)
    try:
        body = response.json()
    except ValueError:
        body = response.text
    print(f"Status: {response.status_code} | Response: {body}")


def run_smart_contract_scenario():
    alice, alice_pk_pqc, alice_sk_pqc = create_alice_account()

    print("Mendaftarkan kunci Alice ke node...")
    reg_result = register_alice_keys(NODE_URL, alice, alice_pk_pqc)
    print(f"Register key response: {reg_result}")

    print("\n1. Deploying Contract...")
    deploy_tx = build_signed_tx(
        ecdsa_account=alice,
        sk_mldsa=alice_sk_pqc,
        recipient=CONTRACT_ADDRESS,
        amount=0,
        nonce=1,
        data_payload={
            "action": "deploy",
            "code": "contract Messenger { store message; }",
        },
    )
    send_tx(NODE_URL, deploy_tx)

    print("\n2. Calling Contract (Menyimpan Pesan)...")
    call_tx = build_signed_tx(
        ecdsa_account=alice,
        sk_mldsa=alice_sk_pqc,
        recipient=CONTRACT_ADDRESS,
        amount=0,
        nonce=2,
        data_payload={
            "action": "call",
            "payload": {"message": "Halo Dunia Web4 dari VOIN!"},
        },
    )
    send_tx(NODE_URL, call_tx)


if __name__ == "__main__":
    try:
        run_smart_contract_scenario()
    except requests.RequestException as exc:
        print(f"Gagal terhubung ke node ({NODE_URL}): {exc}")
