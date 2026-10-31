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

    def test_failed_add_preserves_chain(self):
        import copy
        from unittest.mock import patch

        before = copy.deepcopy(self.chain.chain)
        item = copy.deepcopy(before[1]["transactions"][0])
        tx = item["transaction"]
        tx["nonce"] = 2

        pk, sk = crypto.keygen()
        recipient_pk, _ = crypto.keygen()
        chain = StrictVoinChain({address(pk): 1000}, 0)
        chain.register_validator("v", 50)
        tx = {
            "chain_id": CHAIN_ID,
            "sender": address(pk),
            "recipient": address(recipient_pk),
            "amount": 10,
            "nonce": 1,
        }
        item = {
            "transaction": tx,
            "public_key": pk.hex(),
            "signature": sign_transaction(tx, pk, sk).hex(),
        }
        before = copy.deepcopy(chain.chain)
        with patch("voin.time.time_ns", return_value=0):
            with self.assertRaises(ValueError):
                chain.add_block([item], "v")
        self.assertEqual(chain.chain, before)
        self.assertTrue(chain.validate())

    def test_failed_add_preserves_existing_history(self):
        import copy
        from unittest.mock import patch

        pk, sk = crypto.keygen()
        recipient_pk, _ = crypto.keygen()
        chain = StrictVoinChain({address(pk): 1000}, 0)
        chain.register_validator("v", 50)

        def signed(nonce):
            tx = {
                "chain_id": CHAIN_ID,
                "sender": address(pk),
                "recipient": address(recipient_pk),
                "amount": 10,
                "nonce": nonce,
            }
            return {
                "transaction": tx,
                "public_key": pk.hex(),
                "signature": sign_transaction(tx, pk, sk).hex(),
            }

        chain.add_block([signed(1)], "v")
        before = copy.deepcopy(chain.chain)
        balances_before = chain.balances()
        stamp = before[-1]["timestamp_ns"]
        with patch("voin.time.time_ns", return_value=stamp):
            with self.assertRaises(ValueError):
                chain.add_block([signed(2)], "v")

        self.assertEqual(chain.chain, before)
        self.assertEqual(chain.balances(), balances_before)
        self.assertTrue(chain.validate())

        with patch("voin.time.time_ns", return_value=stamp + 1):
            chain.add_block([signed(2)], "v")
        self.assertEqual(len(chain.chain), 3)
        self.assertEqual(chain.balances()[address(pk)], 980)
        self.assertTrue(chain.validate())
