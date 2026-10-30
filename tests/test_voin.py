import unittest
from voin import VoinChain


class VoinTests(unittest.TestCase):
    def setUp(self):
        self.chain = VoinChain(difficulty=0)
        self.chain.register_validator("validator", 50)

    def tx(self, amount=250, nonce=1):
        return {
            "sender": "alice",
            "recipient": "bob",
            "amount": amount,
            "nonce": nonce,
        }

    def test_transfer(self):
        self.chain.add_block([self.tx()], "validator")
        self.assertEqual(
            self.chain.balances(),
            {"alice": 750, "bob": 250},
        )
        self.assertTrue(self.chain.validate())

    def test_insufficient_balance(self):
        with self.assertRaises(ValueError):
            self.chain.add_block([self.tx(1001)], "validator")
        self.assertEqual(len(self.chain.chain), 1)

    def test_repeated_transaction(self):
        self.chain.add_block([self.tx()], "validator")
        with self.assertRaises(ValueError):
            self.chain.add_block([self.tx()], "validator")

    def test_tampered_block(self):
        self.chain.add_block([self.tx()], "validator")
        self.chain.chain[1]["transactions"][0]["amount"] = 1
        with self.assertRaises(ValueError):
            self.chain.validate()


if __name__ == "__main__":
    unittest.main()
