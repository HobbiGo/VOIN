import copy
from signed_chain_v2 import SignedVoinChainV2
from transactions_v2 import CHAIN_ID, ADDRESS, MAX_VALUE


class GenesisVoinChain(SignedVoinChainV2):
    def __init__(self, allocations, difficulty=2):
        if not isinstance(allocations, dict) or not allocations:
            raise ValueError("Genesis allocations required")
        for account, amount in allocations.items():
            if not isinstance(account, str) or not ADDRESS.fullmatch(account):
                raise ValueError("Invalid genesis address")
            if type(amount) is not int or not 1 <= amount <= MAX_VALUE:
                raise ValueError("Invalid genesis amount")

        super().__init__(allocations, difficulty)
        genesis = {
            "index": 0,
            "timestamp_ns": 0,
            "previous_hash": "0",
            "chain_id": CHAIN_ID,
            "difficulty": difficulty,
            "allocations": copy.deepcopy(allocations),
            "transactions": [],
            "validator": "GENESIS",
            "nonce": 0,
        }
        genesis["hash"] = self._hash(genesis)
        self.chain = [genesis]
        self._trusted_genesis_hash = genesis["hash"]
        self._genesis_difficulty = difficulty

    def _replay(self):
        if self.difficulty != self._genesis_difficulty:
            raise ValueError("Difficulty changed from genesis configuration")
        return super()._replay()
