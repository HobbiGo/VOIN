import unittest
import json
import time
from eth_account import Account
from eth_account.messages import encode_defunct
from voin import VoinChain, canonical_tx_message, canonical_block_message
from security.pqc_signer import generate_keypair, sign as pqc_sign

class VoinTests(unittest.TestCase):

    def setUp(self):
        # 1. Buat akun Pengirim (Alice) TERLEBIH DAHULU
        self.alice_acct = Account.create()
        self.alice_pk_pqc, self.alice_sk_pqc = generate_keypair()

        # 2. Inisialisasi Chain dengan saldo Alice dimasukkan ke Genesis
        allocations = {self.alice_acct.address: 1000}
        self.chain = VoinChain(allocations=allocations, difficulty=0)
        
        # 3. Buat akun Validator
        self.v_acct = Account.create()
        self.v_pk_pqc, self.v_sk_pqc = generate_keypair()
        
        # 4. Daftarkan Validator dengan Public Key
        self.chain.register_validator(
            "validator", 
            50, 
            self.v_acct.address, 
            self.v_pk_pqc.hex()
        )

    def create_signed_tx(self, sender_acct, sender_sk_pqc, recipient, amount, nonce):
        tx = {
            "sender": sender_acct.address,
            "recipient": recipient,
            "amount": amount,
            "nonce": nonce
        }
        msg = canonical_tx_message(tx)
        signable = encode_defunct(primitive=msg)
        tx["sig_ecdsa"] = sender_acct.sign_message(signable).signature.hex()
        tx["sig_mldsa"] = pqc_sign(msg, sender_sk_pqc).hex()
        return tx

    def sign_prepared_block(self, block, validator_acct, validator_sk_pqc):
        block_msg = canonical_block_message(block)
        sig_ecdsa = validator_acct.sign_message(encode_defunct(primitive=block_msg)).signature.hex()
        sig_mldsa = pqc_sign(block_msg, validator_sk_pqc).hex()
        return sig_ecdsa, sig_mldsa

    def test_transfer(self):
        tx = self.create_signed_tx(self.alice_acct, self.alice_sk_pqc, "bob", 250, 1)
        
        # Siapkan block (hash & PoW dibuat oleh ledger)
        block = self.chain.prepare_block([tx], "validator")
        v_sig_e, v_sig_p = self.sign_prepared_block(block, self.v_acct, self.v_sk_pqc)
        
        # Tambahkan ke chain
        self.chain.add_block(block, v_sig_e, v_sig_p)
        
        balances = self.chain.balances()
        self.assertEqual(balances.get(self.alice_acct.address), 750)
        self.assertEqual(balances.get("bob"), 250)

    def test_insufficient_balance(self):
        tx = self.create_signed_tx(self.alice_acct, self.alice_sk_pqc, "bob", 2000, 1)
        
        # _apply akan error di sini karena saldo kurang
        with self.assertRaises(ValueError):
            self.chain.prepare_block([tx], "validator")

    def test_repeated_transaction(self):
        tx1 = self.create_signed_tx(self.alice_acct, self.alice_sk_pqc, "bob", 100, 1)
        block1 = self.chain.prepare_block([tx1], "validator")
        v_sig_e1, v_sig_p1 = self.sign_prepared_block(block1, self.v_acct, self.v_sk_pqc)
        self.chain.add_block(block1, v_sig_e1, v_sig_p1)

        # Coba kirim ulang (nonce 1)
        tx2 = self.create_signed_tx(self.alice_acct, self.alice_sk_pqc, "bob", 100, 1)
        
        with self.assertRaises(ValueError):
            self.chain.prepare_block([tx2], "validator")

    def test_tampered_block(self):
        tx = self.create_signed_tx(self.alice_acct, self.alice_sk_pqc, "bob", 250, 1)
        block = self.chain.prepare_block([tx], "validator")
        v_sig_e, v_sig_p = self.sign_prepared_block(block, self.v_acct, self.v_sk_pqc)
        
        final_block = self.chain.add_block(block, v_sig_e, v_sig_p)
        
        # Modifikasi block secara ilegal
        final_block["transactions"][0]["amount"] = 500
        self.chain.chain[-1] = final_block
        
        with self.assertRaises(ValueError):
            self.chain.validate()

if __name__ == '__main__':
    unittest.main()
