"""
VOIN NONCE ENGINE V1.1

SQLite-based persistent nonce management.

Features:
- Cryptographically secure nonce generation
- Persistent nonce storage
- Atomic nonce consumption
- Replay attack protection
- Wallet-based nonce management
- Security audit integration
"""

import secrets
import time
import sqlite3

from security.storage import VOINStorageEngine


class VOINNonceEngine:

    VERSION = "1.1.0"

    def __init__(self, storage=None):

        self.storage = storage or VOINStorageEngine()

    # Generate and persist nonce
    def generate_nonce(self, wallet_address):

        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        if not wallet_address.strip():
            raise ValueError("Empty wallet address")

        wallet = wallet_address.strip()

        # Retry in the extremely unlikely event of a collision.
        for _ in range(3):

            nonce = secrets.token_hex(32)

            timestamp = int(time.time())

            try:

                self.storage.save_nonce(
                    wallet,
                    nonce
                )

                return {
                    "success": True,
                    "wallet": wallet,
                    "nonce": nonce,
                    "timestamp": timestamp
                }

            except sqlite3.IntegrityError:
                continue

        raise RuntimeError("Unable to generate unique nonce")

    # Verify and atomically consume nonce
    def verify_nonce(self, wallet_address, nonce):

        if not isinstance(wallet_address, str):
            return False

        if not wallet_address.strip():
            return False

        if not isinstance(nonce, str):
            return False

        if not nonce:
            return False

        try:

            return self.storage.consume_nonce(
                wallet_address,
                nonce
            )

        except (ValueError, TypeError):
            return False

    # Engine information
    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Nonce Engine",
            "version": cls.VERSION,
            "storage": "SQLite",
            "cryptographic_random_nonce": True,
            "persistent_nonce_storage": True,
            "atomic_consumption": True,
            "replay_protection": True,
            "restart_protection": True,
            "status": "READY_FOR_TESTING"
        }
