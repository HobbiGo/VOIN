from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict

from eth_utils import keccak
from web3 import Web3

BASE_DIR = Path(__file__).resolve().parent

# ============================================================
# KONFIGURASI DEFAULT MAINNET (BSC MAINNET - CHAIN ID 56)
# ============================================================
MAINNET_RPC_URL = "https://bsc-dataseed.binance.org/"
MAINNET_CHAIN_ID = 56
MAINNET_USDT = "0x55d398326f99059fF775485246999027B3197955"
MAINNET_USDC = "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"

RPC_URL = (os.getenv("BSC_RPC_URL") or MAINNET_RPC_URL).strip()
EXPECTED_CHAIN_ID = int((os.getenv("EXPECTED_CHAIN_ID") or str(MAINNET_CHAIN_ID)).strip())
CHAIN_KEY = (os.getenv("VOIN_NETWORK_KEY") or "bscMainnet").strip()

PRIVATE_KEY = (os.getenv("DEPLOYER_PRIVATE_KEY") or "").strip()
TREASURY_ADDRESS = Web3.to_checksum_address(
    (os.getenv("TREASURY_ADDRESS") or "0xAEb22359588A50e6F746004E66418Eb2c978dAA2").strip()
)

# Jadwal presale / vesting: 1 Des 2026 00:00:00 UTC s/d 31 Des 2028 23:59:59 UTC
START_TIMESTAMP = int(os.getenv("VESTING_START_TIMESTAMP", "1796083200"))
DURATION_SECONDS = int(os.getenv("VESTING_DURATION_SECONDS", str(365 * 24 * 3600)))
INITIAL_BNB_PRICE_USD_WEI = int(os.getenv("INITIAL_BNB_PRICE_USD_WEI", str(600 * 10**18)))
VESTING_FUND_VOIN = int(os.getenv("VESTING_FUND_VOIN", str(156_000_000 * 10**18)))
CONFIRM_MAINNET = (os.getenv("CONFIRM_MAINNET_DEPLOY") or "").strip().lower() in ("1", "true", "yes")

TOKENS_PURCHASED_SIG = (
    "TokensPurchased(address,address,uint256,uint256,uint256,uint256,uint256)"
)
TOKENS_PURCHASED_TOPIC0 = "0x" + keccak(text=TOKENS_PURCHASED_SIG).hex()


def _find_artifact(candidates: list[str]) -> Dict[str, Any]:
    for rel in candidates:
        p = BASE_DIR / rel
        if p.exists() and p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            abi = data.get("abi")
            bytecode = data.get("bytecode") or data.get("data", {}).get("bytecode", {}).get("object")
            if abi and bytecode:
                if isinstance(bytecode, dict):
                    bytecode = bytecode.get("object", "")
                if bytecode and not str(bytecode).startswith("0x"):
                    bytecode = "0x" + str(bytecode)
                return {"abi": abi, "bytecode": bytecode}
    raise FileNotFoundError(f"Artifact tidak ditemukan. Dicari di: {candidates}")


def send_tx(w3: Web3, account: Any, fn: Any, value: int = 0) -> Any:
    nonce = w3.eth.get_transaction_count(account.address)
    tx = fn.build_transaction({
        "from": account.address,
        "nonce": nonce,
        "value": value,
        "gas": 4_000_000,
        "gasPrice": w3.eth.gas_price,
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"[MAINNET TX] Dikirim: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1:
        raise RuntimeError(f"Transaksi Mainnet gagal: {tx_hash.hex()}")
    print(f"[MAINNET TX] Sukses di block {receipt.blockNumber}")
    return receipt


def update_contract_config_js(
    voin_token: str,
    voin_vesting: str,
    voin_presale: str,
    network_key: str = "bscMainnet",
) -> None:
    cfg_path = BASE_DIR / "contract_config.js"
    if not cfg_path.exists():
        return

    content = cfg_path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"({re.escape(network_key)}\s*:\s*\{{.*?contracts\s*:\s*\{{)(.*?)(\}}\s*,)",
        re.DOTALL,
    )
    match = pattern.search(content)
    if not match:
        print("[INFO] Blok contracts di contract_config.js tidak ditemukan; lewati auto-update.")
        return

    updated_contracts = (
        f'\n        voinToken: "{voin_token}",\n'
        f'        voinPresale: "{voin_presale}",\n'
        f'        voinVesting: "{voin_vesting}",\n      '
    )
    new_content = (
        content[: match.start(2)] + updated_contracts + content[match.end(2) :]
    )
    cfg_path.write_text(new_content, encoding="utf-8")
    print(f"[CONFIG] contract_config.js diperbarui untuk '{network_key}'.")


def main() -> None:
    print(f"Network Key              : {CHAIN_KEY}")
    print(f"Expected Chain ID        : {EXPECTED_CHAIN_ID}")
    print(f"RPC URL                  : {RPC_URL}")
    print(f"Treasury Address         : {TREASURY_ADDRESS}")
    print(f"VOIN_TOKENS_PURCHASED_TOPIC0: {TOKENS_PURCHASED_TOPIC0}")

    if not PRIVATE_KEY:
        print(
            "[INFO] DEPLOYER_PRIVATE_KEY belum di-set. "
            "Set DEPLOYER_PRIVATE_KEY dan CONFIRM_MAINNET_DEPLOY=true untuk deploy Mainnet."
        )
        return

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        raise RuntimeError(f"Tidak dapat terhubung ke RPC Mainnet: {RPC_URL}")

    chain_id = w3.eth.chain_id
    if chain_id != EXPECTED_CHAIN_ID:
        raise RuntimeError(
            f"Chain ID tidak sesuai: terhubung ke chainId {chain_id}, diharapkan {EXPECTED_CHAIN_ID} (BSC Mainnet)."
        )

    account = w3.eth.account.from_key(PRIVATE_KEY)
    balance_bnb = Web3.from_wei(w3.eth.get_balance(account.address), "ether")
    print(f"[DEPLOYER] Akun          : {account.address} (Saldo: {balance_bnb} BNB)")

    if not CONFIRM_MAINNET:
        print(
            "[GUARD MAINNET] Deployment dibatalkan demi keamanan. "
            "Set environment variable CONFIRM_MAINNET_DEPLOY=true jika sudah siap deploy ke BSC Mainnet."
        )
        return

    token_art = _find_artifact([
        "artifacts/contracts/vointoken.sol/VoinToken.json",
        "artifacts/vointoken.json",
        "build/VoinToken.json",
    ])
    vesting_art = _find_artifact([
        "artifacts/contracts/voininvesting.sol/VoinVesting.json",
        "artifacts/voininvesting.json",
        "build/VoinVesting.json",
    ])
    presale_art = _find_artifact([
        "artifacts/contracts/voinpresale.sol/VoinPresale.json",
        "artifacts/voinpresale.json",
        "build/VoinPresale.json",
    ])

    # 1. Deploy VoinToken ke Mainnet
    print("\n--- 1. Deploy VoinToken (Mainnet) ---")
    token_ctor = w3.eth.contract(
        abi=token_art["abi"], bytecode=token_art["bytecode"]
    ).constructor(TREASURY_ADDRESS)
    token_rcpt = send_tx(w3, account, token_ctor)
    voin_token_addr = Web3.to_checksum_address(token_rcpt.contractAddress)
    print(f"VoinToken Mainnet : {voin_token_addr}")

    # 2. Deploy VoinVesting ke Mainnet
    print("\n--- 2. Deploy VoinVesting (Mainnet) ---")
    vesting_ctor = w3.eth.contract(
        abi=vesting_art["abi"], bytecode=vesting_art["bytecode"]
    ).constructor(voin_token_addr, START_TIMESTAMP, DURATION_SECONDS)
    vesting_rcpt = send_tx(w3, account, vesting_ctor)
    voin_vesting_addr = Web3.to_checksum_address(vesting_rcpt.contractAddress)
    print(f"VoinVesting Mainnet: {voin_vesting_addr}")

    # 3. Deploy VoinPresale ke Mainnet
    print("\n--- 3. Deploy VoinPresale (Mainnet) ---")
    presale_ctor = w3.eth.contract(
        abi=presale_art["abi"], bytecode=presale_art["bytecode"]
    ).constructor(TREASURY_ADDRESS, voin_vesting_addr, INITIAL_BNB_PRICE_USD_WEI)
    presale_rcpt = send_tx(w3, account, presale_ctor)
    voin_presale_addr = Web3.to_checksum_address(presale_rcpt.contractAddress)
    print(f"VoinPresale Mainnet: {voin_presale_addr}")

    # 4. Hubungkan izin & token pembayaran Mainnet
    print("\n--- 4. Konfigurasi Izin & Token Pembayaran Mainnet ---")
    vesting_contract = w3.eth.contract(address=voin_vesting_addr, abi=vesting_art["abi"])
    presale_contract = w3.eth.contract(address=voin_presale_addr, abi=presale_art["abi"])
    token_contract = w3.eth.contract(address=voin_token_addr, abi=token_art["abi"])

    send_tx(w3, account, vesting_contract.functions.setAllocator(voin_presale_addr, True))

    usdt_addr = (os.getenv("USDT_TOKEN_ADDRESS") or (MAINNET_USDT if chain_id == MAINNET_CHAIN_ID else "")).strip()
    usdc_addr = (os.getenv("USDC_TOKEN_ADDRESS") or (MAINNET_USDC if chain_id == MAINNET_CHAIN_ID else "")).strip()

    for pay_addr in (usdt_addr, usdc_addr):
        if pay_addr:
            send_tx(
                w3,
                account,
                presale_contract.functions.setPaymentToken(
                    Web3.to_checksum_address(pay_addr), True
                ),
            )

    if VESTING_FUND_VOIN > 0:
        deployer_bal = token_contract.functions.balanceOf(account.address).call()
        if deployer_bal >= VESTING_FUND_VOIN:
            send_tx(
                w3,
                account,
                token_contract.functions.transfer(voin_vesting_addr, VESTING_FUND_VOIN),
            )
            print(f"[FUND] {VESTING_FUND_VOIN // 10**18} VOIN ditransfer ke VoinVesting.")
        else:
            print(
                f"[WARN] Saldo deployer ({deployer_bal // 10**18} VOIN) kurang dari {VESTING_FUND_VOIN // 10**18} VOIN. "
                f"Transfer manual dari TREASURY_ADDRESS ({TREASURY_ADDRESS}) ke {voin_vesting_addr} sebelum klaim dibuka."
            )

    deployed_data = {
        "networkKey": CHAIN_KEY,
        "chainId": chain_id,
        "voinToken": voin_token_addr,
        "voinVesting": voin_vesting_addr,
        "voinPresale": voin_presale_addr,
        "VOIN_PRESALE_CONTRACT": voin_presale_addr,
        "VOIN_TOKENS_PURCHASED_TOPIC0": TOKENS_PURCHASED_TOPIC0,
    }
    out_file = BASE_DIR / "deployed_voin_mainnet.json"
    out_file.write_text(json.dumps(deployed_data, indent=2), encoding="utf-8")
    print(f"\n[SAVED] Alamat Mainnet tersimpan di {out_file.name}:")
    print(json.dumps(deployed_data, indent=2))

    update_contract_config_js(
        voin_token=voin_token_addr,
        voin_vesting=voin_vesting_addr,
        voin_presale=voin_presale_addr,
        network_key=CHAIN_KEY,
    )


if __name__ == "__main__":
    main()
