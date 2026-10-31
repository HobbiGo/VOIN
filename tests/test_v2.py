import copy
import unittest
from transactions_v2 import (
    crypto, address, sign_transaction, CHAIN_ID
)
from signed_chain_v2 import SignedVoinChainV2

class V2Tests(unittest.TestCase):
    def setUp(self):
        self.pk, self.sk = crypto.keygen()
        bob_pk, self.bob_sk = crypto.keygen()
        self.bob_pk = bob_pk
        self.alice = address(self.pk)
        self.bob = address(bob_pk)
        self.chain = SignedVoinChainV2(
            {self.alice: 1000}, difficulty=0
        )
        self.chain.register_validator("v", 50)
        self.tx = {
            "chain_id": CHAIN_ID,
            "sender": self.alice, "recipient": self.bob,
            "amount": 250, "nonce": 1
        }

    def envelope(self, tx, pk, sk):
        return {
            "transaction": tx,
            "public_key": pk.hex(),
            "signature": sign_transaction(tx, pk, sk).hex()
        }

    def test_transfer_and_spend(self):
        item = self.envelope(self.tx, self.pk, self.sk)
        self.chain.add_block([item], "v")
        tx = {
            "chain_id": CHAIN_ID,
            "sender": self.bob, "recipient": self.alice,
            "amount": 100, "nonce": 1
        }
        item = self.envelope(tx, self.bob_pk, self.bob_sk)
        self.chain.add_block([item], "v")
        self.assertEqual(self.chain.balances()[self.bob], 150)
        self.assertTrue(self.chain.validate())

    def test_other_network_rejected(self):
        item = self.envelope(self.tx, self.pk, self.sk)
        item["transaction"]["chain_id"] = "other-network"
        with self.assertRaises(ValueError):
            self.chain.add_block([item], "v")
        self.assertEqual(len(self.chain.chain), 1)

    def test_invalid_recipient_rejected(self):
        tx = dict(self.tx, recipient="bob")
        with self.assertRaises(ValueError):
            self.envelope(tx, self.pk, self.sk)

    def test_oversized_key_rejected(self):
        item = self.envelope(self.tx, self.pk, self.sk)
        item["public_key"] += "00"
        with self.assertRaises(ValueError):
            self.chain.add_block([item], "v")

    def test_changed_amount_rejected(self):
        from pqcrypto import InvalidSignatureError
        item = self.envelope(self.tx, self.pk, self.sk)
        item["transaction"]["amount"] = 999
        with self.assertRaises(InvalidSignatureError):
            self.chain.add_block([item], "v")
        self.assertEqual(len(self.chain.chain), 1)

    def test_missing_signature_rejected(self):
        item = self.envelope(self.tx, self.pk, self.sk)
        del item["signature"]
        with self.assertRaises(ValueError):
            self.chain.add_block([item], "v")
        self.assertEqual(len(self.chain.chain), 1)

    def test_too_many_transactions_rejected(self):
        item = self.envelope(self.tx, self.pk, self.sk)
        with self.assertRaises(ValueError):
            self.chain.add_block([item] * 101, "v")
        self.assertEqual(len(self.chain.chain), 1)

    def test_changed_amount_rejected(self):
        from pqcrypto import InvalidSignatureError
        item = self.envelope(self.tx, self.pk, self.sk)
        item["transaction"]["amount"] = 999
        with self.assertRaises(InvalidSignatureError):
            self.chain.add_block([item], "v")
        self.assertEqual(len(self.chain.chain), 1)

    def test_missing_signature_rejected(self):
        item = self.envelope(self.tx, self.pk, self.sk)
        del item["signature"]
        with self.assertRaises(ValueError):
            self.chain.add_block([item], "v")
        self.assertEqual(len(self.chain.chain), 1)

    def test_too_many_transactions_rejected(self):
        item = self.envelope(self.tx, self.pk, self.sk)
        with self.assertRaises(ValueError):
            self.chain.add_block([item] * 101, "v")
        self.assertEqual(len(self.chain.chain), 1)
