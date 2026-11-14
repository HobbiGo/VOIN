"""
VOIN NONCE ENGINE V1.0

Prevents nonce reuse and replay attacks.
"""

import secrets
import time


class VOINNonceEngine:

    VERSION = "1.0.0"

    def __init__(self):
        self.wallet_nonces = {}

    # Generate nonce
    def generate_nonce(self, wallet_address):

        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        wallet = wallet_address.lower()

        nonce = secrets.token_hex(32)

        timestamp = int(time.time())

        self.wallet_nonces[wallet] = {
            "nonce": nonce,
            "created_at": timestamp,
            "used": False
        }

        return {
            "success": True,
            "wallet": wallet_address,
            "nonce": nonce,
            "timestamp": timestamp
        }

    # Verify nonce
    def verify_nonce(self, wallet_address, nonce):

        wallet = wallet_address.lower()

        record = self.wallet_nonces.get(wallet)

        if not record:
            return False

        if record["used"]:
            return False

        if record["nonce"] != nonce:
            return False

        record["used"] = True

        return True

    # Engine information
    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Nonce Engine",
            "version": cls.VERSION,
            "random_nonce": True,
            "replay_protection": True,
            "status": "READY_FOR_TESTING"
        }
