import unittest
import json
import time
from eth_account import Account
from eth_account.messages import encode_defunct
from voin import VoinChain, canonical_tx_message, canonical_block_message
from security.pqc_signer import generate_keypair, sign as pqc_sign

class VoinTests(unittest.TestCase):

    def setUp(self):
        # Gunakan in-memory SQLite agar bersih setiap test
        self.chain = VoinChain(allocations={"alice": 1000}, difficulty=0)
        
        # 1. Buat akun Validator
        self.v_acct = Account.create()
        self.v_pk_pqc, self.v_sk_pqc = generate_keypair()
        
        # 2. Daftarkan Validator dengan Public Key
        self.chain.register_validator(
            "validator", 
            50, 
            self.v_acct.address, 
            self.v_pk_pqc.hex()
        )

        # 3. Buat akun Pengirim (Alice)
        self.alice_acct = Account.create()
        self.alice_pk_pqc, self.alice_sk_pqc = generate_keypair()

        # Daftarkan saldo Alice di state store (karena alice_acct.address berbeda dari string "alice")
        # Kita timpa genesis untuk testing
        self.chain.store.set_account(self.alice_acct.address, 1000, 0)

    def create_signed_tx(self, sender_acct, sender_sk_pqc, recipient, amount, nonce):
        """Helper untuk membuat transaksi yang sudah ditandatangani."""
        tx = {
            "sender": sender_acct.address,
            "recipient": recipient,
            "amount": amount,
            "nonce": nonce
        }
        msg = canonical_tx_message(tx)
        
        # Tanda tangan ECDSA
        signable = encode_defunct(primitive=msg)
        tx["sig_ecdsa"] = sender_acct.sign_message(signable).signature.hex()
        
        # Tanda tangan ML-DSA
        tx["sig_mldsa"] = pqc_sign(msg, sender_sk_pqc).hex()
        
        return tx

    def create_signed_block_sig(self, block, validator_acct, validator_sk_pqc):
        """Helper untuk membuat signature validator untuk block."""
        block_msg = canonical_block_message(block)
        sig_ecdsa = validator_acct.sign_message(encode_defunct(primitive=block_msg)).signature.hex()
        sig_mldsa = pqc_sign(block_msg, validator_sk_pqc).hex()
        return sig_ecdsa, sig_mldsa

    def test_transfer(self):
        tx = self.create_signed_tx(self.alice_acct, self.alice_sk_pqc, "bob", 250, 1)
        
        # Buat block sementara (tanpa hash) untuk ditandatangani validator
        temp_block = {
            "index": len(self.chain.chain),
            "timestamp_ns": time.time_ns(),
            "previous_hash": self.chain.chain[-1]["hash"],
            "transactions": [tx],
            "validator": "validator",
            "nonce": 0
        }
        v_sig_e, v_sig_p = self.create_signed_block_sig(temp_block, self.v_acct, self.v_sk_pqc)
        
        # Tambahkan block
        self.chain.add_block([tx], "validator", v_sig_e, v_sig_p)
        
        # Cek saldo
        self.assertEqual(self.chain.store.get_account(self.alice_acct.address)["balance"], 750)
        self.assertEqual(self.chain.store.get_account("bob")["balance"], 250)

    def test_insufficient_balance(self):
        tx = self.create_signed_tx(self.alice_acct, self.alice_sk_pqc, "bob", 2000, 1)
        
        temp_block = {
            "index": len(self.chain.chain),
            "timestamp_ns": time.time_ns(),
            "previous_hash": self.chain.chain[-1]["hash"],
            "transactions": [tx],
            "validator": "validator",
            "nonce": 0
        }
        v_sig_e, v_sig_p = self.create_signed_block_sig(temp_block, self.v_acct, self.v_sk_pqc)
        
        with self.assertRaises(ValueError):
            self.chain.add_block([tx], "validator", v_sig_e, v_sig_p)

    def test_repeated_transaction(self):
        tx1 = self.create_signed_tx(self.alice_acct, self.alice_sk_pqc, "bob", 100, 1)
        
        temp_block1 = {
            "index": len(self.chain.chain),
            "timestamp_ns": time.time_ns(),
            "previous_hash": self.chain.chain[-1]["hash"],
            "transactions": [tx1],
            "validator": "validator",
            "nonce": 0
        }
        v_sig_e1, v_sig_p1 = self.create_signed_block_sig(temp_block1, self.v_acct, self.v_sk_pqc)
        self.chain.add_block([tx1], "validator", v_sig_e1, v_sig_p1)

        # Coba kirim ulang transaksi yang sama (nonce 1)
        tx2 = self.create_signed_tx(self.alice_acct, self.alice_sk_pqc, "bob", 100, 1)
        
        temp_block2 = {
            "index": len(self.chain.chain),
            "timestamp_ns": time.time_ns(),
            "previous_hash": self.chain.chain[-1]["hash"],
            "transactions": [tx2],
            "validator": "validator",
            "nonce": 0
        }
        v_sig_e2, v_sig_p2 = self.create_signed_block_sig(temp_block2, self.v_acct, self.v_sk_pqc)

        with self.assertRaises(ValueError):
            self.chain.add_block([tx2], "validator", v_sig_e2, v_sig_p2)

    def test_tampered_block(self):
        tx = self.create_signed_tx(self.alice_acct, self.alice_sk_pqc, "bob", 250, 1)
        
        temp_block = {
            "index": len(self.chain.chain),
            "timestamp_ns": time.time_ns(),
            "previous_hash": self.chain.chain[-1]["hash"],
            "transactions": [tx],
            "validator": "validator",
            "nonce": 0
        }
        v_sig_e, v_sig_p = self.create_signed_block_sig(temp_block, self.v_acct, self.v_sk_pqc)
        
        block = self.chain.add_block([tx], "validator", v_sig_e, v_sig_p)
        
        # Modifikasi block secara ilegal
        block["transactions"][0]["amount"] = 500
        self.chain.chain[-1] = block
        
        with self.assertRaises(ValueError):
            self.chain.validate()

if __name__ == '__main__':
    unittest.main()
