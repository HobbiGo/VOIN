import copy
import unittest
from pqcrypto import InvalidSignatureError
from signatures import keygen, address, sign_transaction
from signed_chain import SignedVoinChain

class SignedChainTests(unittest.TestCase):
    def setUp(self):
        pk, sk = keygen()
        self.chain = SignedVoinChain(
            allocations={address(pk): 1000}, difficulty=0
        )
        self.chain.register_validator("v", 50)
        tx = {
            "sender": address(pk), "recipient": "bob",
            "amount": 250, "nonce": 1
        }
        self.item = {
            "transaction": tx,
            "public_key": pk.hex(),
            "signature": sign_transaction(tx, pk, sk).hex()
        }

    def test_valid(self):
        self.chain.add_block([self.item], "v")
        self.assertEqual(self.chain.balances()["bob"], 250)
        self.assertTrue(self.chain.validate())

    def test_unsigned_rejected(self):
        with self.assertRaises(ValueError):
            self.chain.add_block([self.item["transaction"]], "v")
        self.assertEqual(len(self.chain.chain), 1)

    def test_changed_amount_rejected(self):
        item = copy.deepcopy(self.item)
        item["transaction"]["amount"] = 999
        with self.assertRaises(InvalidSignatureError):
            self.chain.add_block([item], "v")
        self.assertEqual(len(self.chain.chain), 1)

    def test_replay_rejected(self):
        self.chain.add_block([self.item], "v")
        with self.assertRaises(ValueError):
            self.chain.add_block([self.item], "v")
