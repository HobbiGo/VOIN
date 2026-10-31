import unittest
from genesis_chain import GenesisVoinChain

A = "voin_" + "a" * 64
B = "voin_" + "b" * 64


class GenesisTests(unittest.TestCase):
    def test_same_configuration_same_hash(self):
        first = GenesisVoinChain({A: 1000, B: 500}, 0)
        second = GenesisVoinChain({B: 500, A: 1000}, 0)
        self.assertEqual(first.chain[0], second.chain[0])
        self.assertTrue(first.validate())
        self.assertTrue(second.validate())

    def test_different_allocation_different_hash(self):
        first = GenesisVoinChain({A: 1000}, 0)
        second = GenesisVoinChain({A: 999}, 0)
        self.assertNotEqual(
            first.chain[0]["hash"], second.chain[0]["hash"]
        )

    def test_difficulty_change_rejected(self):
        chain = GenesisVoinChain({A: 1000}, 2)
        chain.difficulty = 0
        with self.assertRaises(ValueError):
            chain.validate()

    def test_genesis_rewrite_rejected(self):
        chain = GenesisVoinChain({A: 1000}, 0)
        chain.chain[0]["allocations"][A] = 9999
        chain.chain[0]["hash"] = chain._hash(chain.chain[0])
        with self.assertRaises(ValueError):
            chain.validate()

    def test_invalid_genesis_address_rejected(self):
        with self.assertRaises(ValueError):
            GenesisVoinChain({"alice": 1000}, 0)
