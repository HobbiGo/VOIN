"""Educational single-process ledger. NOT a cryptocurrency or PQC implementation."""
import copy
import hashlib
import json
import time


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def positive_int(value):
    return type(value) is int and value > 0


class VoinChain:
    def __init__(self, allocations=None, difficulty=2):
        if type(difficulty) is not int or not 0 <= difficulty <= 4:
            raise ValueError("Difficulty must be an integer from 0 to 4")
        if allocations is None:
            allocations = {"alice": 1000}
        if not isinstance(allocations, dict) or not allocations:
            raise ValueError("Genesis allocations must be a non-empty dictionary")
        if any(not isinstance(a, str) or not a.strip() or not positive_int(v)
               for a, v in allocations.items()):
            raise ValueError("Genesis requires named accounts and positive integer balances")
        self.difficulty = difficulty
        genesis = {"index": 0, "timestamp_ns": time.time_ns(),
                   "previous_hash": "0", "allocations": copy.deepcopy(allocations),
                   "transactions": [], "validator": "GENESIS", "nonce": 0}
        genesis["hash"] = self._hash(genesis)
        self._trusted_genesis_hash = genesis["hash"]
        self.chain = [genesis]
        self.validators = {}

    @staticmethod
    def _hash(block):
        return digest({k: v for k, v in block.items() if k != "hash"})

    def register_validator(self, address, demo_stake):
        # Metadata only: no deposited stake, consensus, rewards, or slashing.
        if not isinstance(address, str) or not address.strip() or not positive_int(demo_stake):
            raise ValueError("Validator requires a name and positive integer demo stake")
        self.validators[address] = demo_stake

    @staticmethod
    def _apply(balances, nonces, transactions):
        if not isinstance(transactions, list) or not transactions:
            raise ValueError("Provide a non-empty transaction list")
        for tx in transactions:
            if not isinstance(tx, dict) or set(tx) != {"sender", "recipient", "amount", "nonce"}:
                raise ValueError("Invalid transaction fields")
            sender, recipient = tx["sender"], tx["recipient"]
            if any(not isinstance(a, str) or not a.strip() for a in (sender, recipient)):
                raise ValueError("Invalid account")
            if sender == recipient:
                raise ValueError("Sender and recipient must differ")
            if not positive_int(tx["amount"]) or not positive_int(tx["nonce"]):
                raise ValueError("Amount and nonce must be positive integers")
            if tx["nonce"] != nonces.get(sender, 0) + 1:
                raise ValueError("Invalid nonce: duplicate or out-of-order transaction")
            if balances.get(sender, 0) < tx["amount"]:
                raise ValueError("Insufficient balance")
            balances[sender] -= tx["amount"]
            balances[recipient] = balances.get(recipient, 0) + tx["amount"]
            nonces[sender] = tx["nonce"]

    def _replay(self):
        genesis = self.chain[0]
        if self._hash(genesis) != self._trusted_genesis_hash or genesis["hash"] != self._trusted_genesis_hash:
            raise ValueError("Genesis was modified")
        balances = copy.deepcopy(genesis["allocations"])
        nonces = {}
        for index, block in enumerate(self.chain[1:], 1):
            if block["index"] != index or block["previous_hash"] != self.chain[index - 1]["hash"]:
                raise ValueError("Broken block linkage")
            if self._hash(block) != block["hash"] or not block["hash"].startswith("0" * self.difficulty):
                raise ValueError("Invalid block hash or proof of work")
            self._apply(balances, nonces, block["transactions"])
        return balances, nonces

    def validate(self):
        self._replay()
        return True

    def balances(self):
        return self._replay()[0]

    def add_block(self, transactions, validator):
        if validator not in self.validators:
            raise ValueError("Unregistered demo validator")
        balances, nonces = self._replay()
        transactions = copy.deepcopy(transactions)
        self._apply(balances, nonces, transactions)
        block = {"index": len(self.chain), "timestamp_ns": time.time_ns(),
                 "previous_hash": self.chain[-1]["hash"], "transactions": transactions,
                 "validator": validator, "nonce": 0}
        block["hash"] = self._hash(block)
        while not block["hash"].startswith("0" * self.difficulty):
            block["nonce"] += 1
            block["hash"] = self._hash(block)
        self.chain.append(block)
        return copy.deepcopy(block)


if __name__ == "__main__":
    ledger = VoinChain()
    ledger.register_validator("validator_alpha", 50000)
    block = ledger.add_block([
        {"sender": "alice", "recipient": "bob", "amount": 250, "nonce": 1}
    ], "validator_alpha")
    print("VOIN local educational simulator")
    print("Block hash:", block["hash"])
    print("Balances:", ledger.balances())
    print("Chain integrity:", ledger.validate())
    print("Transaction authentication and post-quantum signatures: NOT IMPLEMENTED")
