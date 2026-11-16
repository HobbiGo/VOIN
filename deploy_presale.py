import requests
import json
import inspect
from eth_account import Account
from eth_account.messages import encode_defunct
from security.pqc_signer import generate_keypair, sign as pqc_sign
from voin import canonical_tx_message
from presale_contract import VOINPresaleContract

NODE_URL = "http://127.0.0.1:5000"

# 1. Setup Akun Developer (Anda)
dev_acct = Account.create()
dev_pk_pqc, dev_sk_pqc = generate_keypair()

print(f"Developer Address: {dev_acct.address}")

# Daftarkan kunci publik ke node agar bisa memverifikasi transaksi kita
requests.post(f"{NODE_URL}/register_key", json={
    "address": dev_acct.address, "pk_ecdsa": dev_acct.address, "pk_mldsa": dev_pk_pqc.hex()
})

# 2. Ambil Source Code Smart Contract
contract_code = inspect.getsource(VOINPresaleContract)

# 3. Buat Transaksi Deploy
contract_address = "0xVOIN_PRESALE_CONTRACT_2026"
tx = {
    "sender": dev_acct.address,
    "recipient": contract_address,
    "amount": 0,
    "nonce": 1,
    "data": {
        "action": "deploy",
        "code": contract_code
    }
}

# Tanda tangani transaksi
msg = canonical_tx_message(tx)
tx["sig_ecdsa"] = dev_acct.sign_message(encode_defunct(primitive=msg)).signature.hex()
tx["sig_mldsa"] = pqc_sign(msg, dev_sk_pqc).hex()

# 4. Kirim ke Node
print("Mengirim Smart Contract Presale ke Jaringan VOIN...")
res = requests.post(f"{NODE_URL}/transaction", json=tx)
print("Respons Node:", res.json())
print("Smart Contract berhasil di-deploy! Menunggu ditambang ke dalam blok (Mempool).")
