from voin import VoinChain
from signatures import verify_transaction

class SignedVoinChain(VoinChain):
    @staticmethod
    def _apply(balances, nonces, transactions):
        if not isinstance(transactions, list) or not transactions:
            raise ValueError("Provide signed transactions")
        payloads = []
        for item in transactions:
            if not isinstance(item, dict) or set(item) != {
                "transaction", "public_key", "signature"
            }:
                raise ValueError("Signed transaction required")
            tx = item["transaction"]
            pk = bytes.fromhex(item["public_key"])
            sig = bytes.fromhex(item["signature"])
            verify_transaction(tx, pk, sig)
            payloads.append(tx)
        VoinChain._apply(balances, nonces, payloads)
