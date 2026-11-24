from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

from eth_utils import keccak
from web3 import Web3

BASE_DIR = Path(__file__).resolve().parent

RPC_URL = os.getenv("BSC_RPC_URL", "https://data-seed-prebsc-1-s1.binance.org:8545/")
PRIVATE_KEY = (os.getenv("DEPLOYER_PRIVATE_KEY") or "").strip()
TREASURY_ADDRESS = Web3.to_checksum_address(
    os.getenv("TREASURY_ADDRESS", "0xAEb22359588A50e6F746004E66418Eb2c978dAA2")
)
CHAIN_KEY = (os.getenv("VOIN_NETWORK_KEY") or "bscTestnet").strip()

START_TIMESTAMP = int(os.getenv("VESTING_START_TIMESTAMP", "1796083200"))
DURATION_SECONDS = int(os.getenv("VESTING_DURATION_SECONDS", str(365 * 24 * 3600)))
INITIAL_BNB_PRICE_USD_WEI = int(os.getenv("INITIAL_BNB_PRICE_USD_WEI", str(600 * 10**18)))
VESTING_FUND_VOIN = int(os.getenv("VESTING_FUND_VOIN", str(156_000_000 * 10**18)))

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
    print(f"[TX] Dikirim: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1:
        raise RuntimeError(f"Transaksi gagal on-chain: {tx_hash.hex()}")
    print(f"[TX] Sukses di block {receipt.blockNumber}")
    return receipt


def update_contract_config_js(
    voin_token: str,
    voin_vesting: str,
    voin_presale: str,
    network_key: str = "bscTestnet",
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
    print(f"[CONFIG] contract_config.js diperbarui untuk jaringan '{network_key}'.")


def main() -> None:
    print(f"VOIN_TOKENS_PURCHASED_TOPIC0 = {TOKENS_PURCHASED_TOPIC0}")

    if not PRIVATE_KEY:
        print(
            "[INFO] DEPLOYER_PRIVATE_KEY belum di-set. "
            "Set environment variable DEPLOYER_PRIVATE_KEY untuk mengeksekusi deploy ke blockchain."
        )
        return

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        raise RuntimeError(f"Tidak dapat terhubung ke RPC: {RPC_URL}")

    account = w3.eth.account.from_key(PRIVATE_KEY)
    print(f"[DEPLOYER] Akun: {account.address}")
    print(f"[TREASURY] Penerima awal: {TREASURY_ADDRESS}")

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

    # 1. Deploy VoinToken
    print("\n--- 1. Deploy VoinToken ---")
    token_ctor = w3.eth.contract(
        abi=token_art["abi"], bytecode=token_art["bytecode"]
    ).constructor(TREASURY_ADDRESS)
    token_rcpt = send_tx(w3, account, token_ctor)
    voin_token_addr = Web3.to_checksum_address(token_rcpt.contractAddress)
    print(f"VoinToken: {voin_token_addr}")

    # 2. Deploy VoinVesting
    print("\n--- 2. Deploy VoinVesting ---")
    vesting_ctor = w3.eth.contract(
        abi=vesting_art["abi"], bytecode=vesting_art["bytecode"]
    ).constructor(voin_token_addr, START_TIMESTAMP, DURATION_SECONDS)
    vesting_rcpt = send_tx(w3, account, vesting_ctor)
    voin_vesting_addr = Web3.to_checksum_address(vesting_rcpt.contractAddress)
    print(f"VoinVesting: {voin_vesting_addr}")

    # 3. Deploy VoinPresale
    print("\n--- 3. Deploy VoinPresale ---")
    presale_ctor = w3.eth.contract(
        abi=presale_art["abi"], bytecode=presale_art["bytecode"]
    ).constructor(TREASURY_ADDRESS, voin_vesting_addr, INITIAL_BNB_PRICE_USD_WEI)
    presale_rcpt = send_tx(w3, account, presale_ctor)
    voin_presale_addr = Web3.to_checksum_address(presale_rcpt.contractAddress)
    print(f"VoinPresale: {voin_presale_addr}")

    # 4. Hubungkan izin & transfer alokasi token ke VoinVesting
    print("\n--- 4. Konfigurasi Izin & Alokasi Token ---")
    vesting_contract = w3.eth.contract(address=voin_vesting_addr, abi=vesting_art["abi"])
    presale_contract = w3.eth.contract(address=voin_presale_addr, abi=presale_art["abi"])
    token_contract = w3.eth.contract(address=voin_token_addr, abi=token_art["abi"])

    send_tx(w3, account, vesting_contract.functions.setAllocator(voin_presale_addr, True))

    for env_key in ("USDT_TOKEN_ADDRESS", "USDC_TOKEN_ADDRESS"):
        pay_addr = (os.getenv(env_key) or "").strip()
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
                f"[WARN] Saldo deployer ({deployer_bal // 10**18} VOIN) kurang dari target transfer "
                f"({VESTING_FUND_VOIN // 10**18} VOIN). Transfer manual dari TREASURY_ADDRESS "
                f"({TREASURY_ADDRESS}) ke {voin_vesting_addr} sebelum klaim dibuka."
            )

    deployed_data = {
        "networkKey": CHAIN_KEY,
        "voinToken": voin_token_addr,
        "voinVesting": voin_vesting_addr,
        "voinPresale": voin_presale_addr,
        "VOIN_PRESALE_CONTRACT": voin_presale_addr,
        "VOIN_TOKENS_PURCHASED_TOPIC0": TOKENS_PURCHASED_TOPIC0,
    }
    out_file = BASE_DIR / "deployed_voin_addresses.json"
    out_file.write_text(json.dumps(deployed_data, indent=2), encoding="utf-8")
    print(f"\n[SAVED] Alamat tersimpan di {out_file.name}:")
    print(json.dumps(deployed_data, indent=2))

    update_contract_config_js(
        voin_token=voin_token_addr,
        voin_vesting=voin_vesting_addr,
        voin_presale=voin_presale_addr,
        network_key=CHAIN_KEY,
    )


if __name__ == "__main__":
    main()
