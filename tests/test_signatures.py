import unittest
from pqcrypto import InvalidSignatureError
from signatures import (
    keygen, address, sign_transaction, verify_transaction
)


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.pk, self.sk = keygen()
        self.tx = {
            "sender": address(self.pk),
            "recipient": "bob",
            "amount": 250,
            "nonce": 1,
        }

    def test_valid_signature(self):
        sig = sign_transaction(self.tx, self.pk, self.sk)
        self.assertTrue(verify_transaction(self.tx, self.pk, sig))

    def test_changed_amount_rejected(self):
        sig = sign_transaction(self.tx, self.pk, self.sk)
        changed = dict(self.tx, amount=999)
        with self.assertRaises(InvalidSignatureError):
            verify_transaction(changed, self.pk, sig)

    def test_wrong_sender_key_rejected(self):
        sig = sign_transaction(self.tx, self.pk, self.sk)
        other_pk, _ = keygen()
        with self.assertRaises(ValueError):
            verify_transaction(self.tx, other_pk, sig)


if __name__ == "__main__":
    unittest.main()
