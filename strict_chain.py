from genesis_chain import GenesisVoinChain


class StrictVoinChain(GenesisVoinChain):
    def _replay(self):
        if not isinstance(self.chain, list) or not self.chain:
            raise ValueError("Missing chain")
        previous_time = 0
        fields = {
            "index", "timestamp_ns", "previous_hash",
            "transactions", "validator", "nonce", "hash"
        }
        for index, block in enumerate(self.chain[1:], 1):
            if not isinstance(block, dict) or set(block) != fields:
                raise ValueError("Invalid block fields")
            if type(block["index"]) is not int or block["index"] != index:
                raise ValueError("Invalid block index")
            stamp = block["timestamp_ns"]
            if type(stamp) is not int or stamp <= previous_time:
                raise ValueError("Invalid block timestamp")
            previous_time = stamp
            if type(block["nonce"]) is not int or block["nonce"] < 0:
                raise ValueError("Invalid block nonce")
            for name in ("hash", "previous_hash"):
                value = block[name]
                if not isinstance(value, str) or len(value) != 64:
                    raise ValueError("Invalid hash format")
                if any(c not in "0123456789abcdef" for c in value):
                    raise ValueError("Invalid hash encoding")
            validator = block["validator"]
            if not isinstance(validator, str) or not validator.strip():
                raise ValueError("Invalid validator name")
        return super()._replay()
