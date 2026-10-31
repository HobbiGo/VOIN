from voin import VoinChain
from transactions_v2 import verify_transaction, crypto

MAX_TRANSACTIONS = 100


def decode_hex(value, byte_length):
    if not isinstance(value, str):
        raise ValueError("Expected hex string")
    if len(value) != byte_length * 2:
        raise ValueError("Invalid hex length")
    if any(c not in "0123456789abcdef" for c in value):
        raise ValueError("Invalid hex encoding")
    return bytes.fromhex(value)


class SignedVoinChainV2(VoinChain):
    @staticmethod
    def _apply(balances, nonces, transactions):
        if not isinstance(transactions, list):
            raise ValueError("Expected transaction list")
        if not 1 <= len(transactions) <= MAX_TRANSACTIONS:
            raise ValueError("Invalid transaction count")
        payloads = []
        for item in transactions:
            if not isinstance(item, dict) or set(item) != {
                "transaction", "public_key", "signature"
            }:
                raise ValueError("Signed transaction required")
            pk = decode_hex(item["public_key"], crypto.PUBLIC_KEY_SIZE)
            sig = decode_hex(item["signature"], crypto.SIGNATURE_SIZE)
            tx = item["transaction"]
            verify_transaction(tx, pk, sig)
            payloads.append({
                name: tx[name] for name in
                ("sender", "recipient", "amount", "nonce")
            })
        VoinChain._apply(balances, nonces, payloads)
