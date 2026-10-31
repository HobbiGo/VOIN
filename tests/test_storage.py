import json
import tempfile
import unittest
from pathlib import Path
from ledger_storage import save_ledger, load_ledger
from strict_chain import StrictVoinChain
from transactions_v2 import crypto, address, sign_transaction, CHAIN_ID


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "ledger.json"
        pk, sk = crypto.keygen()
        recipient_pk, _ = crypto.keygen()
        self.allocations = {address(pk): 1000}
        self.chain = StrictVoinChain(self.allocations, 0)
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

    def test_round_trip(self):
        save_ledger(self.chain, self.path)
        loaded = load_ledger(self.path, self.allocations, 0)
        self.assertEqual(loaded.chain, self.chain.chain)
        self.assertEqual(loaded.balances(), self.chain.balances())
        self.assertTrue(loaded.validate())

    def test_wrong_genesis_rejected(self):
        save_ledger(self.chain, self.path)
        wrong = {key: 999 for key in self.allocations}
        with self.assertRaises(ValueError):
            load_ledger(self.path, wrong, 0)

    def test_modified_block_rejected(self):
        save_ledger(self.chain, self.path)
        document = json.loads(self.path.read_text())
        document["chain"][1]["transactions"][0]["transaction"]["amount"] = 999
        self.path.write_text(json.dumps(document))
        with self.assertRaises(ValueError):
            load_ledger(self.path, self.allocations, 0)

    def test_duplicate_json_field_rejected(self):
        self.path.write_text(
            '{"format":"voin-snapshot-v1","chain":[],"chain":[]}'
        )
        with self.assertRaises(ValueError):
            load_ledger(self.path, self.allocations, 0)

    def test_failed_save_preserves_existing_file(self):
        save_ledger(self.chain, self.path)
        before = self.path.read_bytes()
        self.chain.chain[1]["nonce"] = -1
        with self.assertRaises(ValueError):
            save_ledger(self.chain, self.path)
        self.assertEqual(self.path.read_bytes(), before)
