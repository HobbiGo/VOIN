import unittest
import json
import time
from eth_account import Account
from eth_account.messages import encode_defunct
from voin import VoinChain, canonical_tx_message, canonical_block_message
from security.pqc_signer import generate_keypair, sign as pqc_sign
from wallet.verification import register_account_keys

class VoinTests(unittest.TestCase):
    def setUp(self):
        self.alice_acct = Account.create()
        self.alice_pk_pqc, self.alice_sk_pqc = generate_keypair()
        register_account_keys(self.alice_acct.address, self.alice_acct.address, self.alice_pk_pqc.hex())

        allocations = {self.alice_acct.address: 1000}
        self.chain = VoinChain(genesis_data={"allocations": allocations}, difficulty=0)
        
        self.v_acct = Account.create()
        self.v_pk_pqc, self.v_sk_pqc = generate_keypair()
        self.validator_id = self.v_acct.address
        self.chain.register_validator(self.validator_id, 50, self.v_acct.address, self.v_pk_pqc.hex())

    def create_signed_tx(self, sender_acct, sender_sk_pqc, recipient, amount, nonce, data=None):
        if data is None: data = {}
        tx = {"sender": sender_acct.address, "recipient": recipient, "amount": amount, "nonce": nonce, "data": data}
        msg = canonical_tx_message(tx)
        tx["sig_ecdsa"] = sender_acct.sign_message(encode_defunct(primitive=msg)).signature.hex()
        tx["sig_mldsa"] = pqc_sign(msg, sender_sk_pqc).hex()
        return tx

    def test_transfer(self):
        tx = self.create_signed_tx(self.alice_acct, self.alice_sk_pqc, "bob", 250, 1)
        block = self.chain.prepare_block([tx], self.validator_id)
        v_sig_e = self.v_acct.sign_message(encode_defunct(primitive=canonical_block_message(block))).signature.hex()
        v_sig_p = pqc_sign(canonical_block_message(block), self.v_sk_pqc).hex()
        self.chain.add_block(block, v_sig_e, v_sig_p)
        
        self.assertEqual(self.chain.balances().get(self.alice_acct.address), 750)

    def test_deploy_contract(self):
        tx = self.create_signed_tx(self.alice_acct, self.alice_sk_pqc, "0xContract", 0, 1, data={"action": "deploy", "code": "test"})
        block = self.chain.prepare_block([tx], self.validator_id)
        v_sig_e = self.v_acct.sign_message(encode_defunct(primitive=canonical_block_message(block))).signature.hex()
        v_sig_p = pqc_sign(canonical_block_message(block), self.v_sk_pqc).hex()
        self.chain.add_block(block, v_sig_e, v_sig_p)
        
        contract = self.chain.store.get_contract("0xContract")
        self.assertIsNotNone(contract)

if __name__ == '__main__':
    unittest.main()
