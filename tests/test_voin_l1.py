import json
import sqlite3
import time
import hashlib
import os
from eth_account import Account
from eth_account.messages import encode_defunct
from security.pqc_signer import generate_keypair, sign as pqc_sign, verify as pqc_verify

# ==========================================
# 1. STATE STORE (Persistence)
# ==========================================
class StateStore:
    def __init__(self, path="voin_test.db"):
        self.path = path
        with sqlite3.connect(self.path) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY, hash TEXT, raw TEXT)")
            conn.execute("CREATE TABLE IF NOT EXISTS accounts (address TEXT PRIMARY KEY, balance INTEGER)")

    def save_block(self, height, block_hash, raw_block):
        with sqlite3.connect(self.path) as conn:
            conn.execute("INSERT INTO blocks (height, hash, raw) VALUES (?, ?, ?)", (height, block_hash, raw_block))

    def get_balance(self, address):
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT balance FROM accounts WHERE address = ?", (address,)).fetchone()
            return row[0] if row else 0

    def set_balance(self, address, balance):
        with sqlite3.connect(self.path) as conn:
            conn.execute("INSERT OR REPLACE INTO accounts (address, balance) VALUES (?, ?)", (address, balance))

# ==========================================
# 2. LEDGER CORE (Dengan ML-DSA)
# ==========================================
class VoinL1Chain:
    def __init__(self, store):
        self.store = store
        self.difficulty = 1

    def _hash(self, data):
        raw = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()

    def process_transaction(self, tx):
        # 1. Ambil data kanonik
        payload = {k: tx[k] for k in ("sender", "recipient", "amount", "nonce")}
        message = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # 2. Verifikasi ECDSA
        signable = encode_defunct(primitive=message)
        recovered = Account.recover_message(signable, signature=tx["sig_ecdsa"])
        if recovered.lower() != tx["sender"].lower():
            raise ValueError("Signature ECDSA tidak valid!")

        # 3. Verifikasi ML-DSA
        if not pqc_verify(message, bytes.fromhex(tx["sig_mldsa"]), bytes.fromhex(tx["pk_mldsa"])):
            raise ValueError("Signature ML-DSA tidak valid!")

        # 4. Eksekusi Transfer (sederhana)
        sender_bal = self.store.get_balance(tx["sender"])
        if sender_bal < tx["amount"]:
            raise ValueError("Saldo tidak cukup!")
        
        self.store.set_balance(tx["sender"], sender_bal - tx["amount"])
        self.store.set_balance(tx["recipient"], self.store.get_balance(tx["recipient"]) + tx["amount"])
        
        return True

# ==========================================
# 3. DEMO (Uji Coba Pengiriman)
# ==========================================
if __name__ == "__main__":
    print("=== VOIN L1 TEST DENGAN ML-DSA ===")
    
    # Hapus DB lama jika ada
    if os.path.exists("voin_test.db"): os.remove("voin_test.db")
    store = StateStore()
    ledger = VoinL1Chain(store)

    # Setup Akun
    alice_evm = Account.create()
    alice_pk_pqc, alice_sk_pqc = generate_keypair()
    store.set_balance(alice_evm.address, 1000) # Alice punya 1000 koin

    print(f"Alamat Alice: {alice_evm.address}")
    print(f"Saldo Awal Alice: {store.get_balance(alice_evm.address)}")

    # Buat Transaksi
    tx = {
        "sender": alice_evm.address,
        "recipient": "0xBobAddress",
        "amount": 250,
        "nonce": 1
    }

    # Tanda Tangan (Hybrid)
    payload = {k: tx[k] for k in ("sender", "recipient", "amount", "nonce")}
    message = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    tx["sig_ecdsa"] = alice_evm.sign_message(encode_defunct(primitive=message)).signature.hex()
    tx["sig_mldsa"] = pqc_sign(message, alice_sk_pqc).hex()
    tx["pk_mldsa"] = alice_pk_pqc.hex()

    print("\nMemproses transaksi...")
    try:
        ledger.process_transaction(tx)
        print("✅ TRANSAKSI BERHASIL DIPROSES!")
    except Exception as e:
        print(f"❌ GAGAL: {e}")

    print(f"Saldo Akhir Alice: {store.get_balance(alice_evm.address)}")
    print(f"Saldo Bob: {store.get_balance('0xBobAddress')}")
