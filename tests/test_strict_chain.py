import unittest
from strict_chain import StrictVoinChain
from transactions_v2 import crypto, address, sign_transaction, CHAIN_ID


class StrictChainTests(unittest.TestCase):
    def setUp(self):
        pk, sk = crypto.keygen()
        recipient_pk, _ = crypto.keygen()
        self.chain = StrictVoinChain({address(pk): 1000}, 0)
        self.chain.register_validator("v", 50)
        tx = {
            "chain_id": CHAIN_ID,
            "sender": address(pk),
            "recipient": address(recipient_pk),
            "amount": 250,
            "nonce": 1,
        }
        self.chain.add_block([{
            "transaction": tx,
            "public_key": pk.hex(),
            "signature": sign_transaction(tx, pk, sk).hex(),
        }], "v")

    def test_valid_block(self):
        self.assertTrue(self.chain.validate())

    def reject_change(self, field, value):
        block = self.chain.chain[1]
        block[field] = value
        block["hash"] = self.chain._hash(block)
        with self.assertRaises(ValueError):
            self.chain.validate()

    def test_boolean_index_rejected(self):
        self.reject_change("index", True)

    def test_negative_nonce_rejected(self):
        self.reject_change("nonce", -1)

    def test_zero_timestamp_rejected(self):
        self.reject_change("timestamp_ns", 0)

    def test_extra_field_rejected(self):
        self.reject_change("unexpected", "data")

    def test_empty_validator_rejected(self):
        self.reject_change("validator", "")

    def test_bad_previous_hash_rejected(self):
        self.reject_change("previous_hash", "z" * 64)
