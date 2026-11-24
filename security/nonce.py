"""
VOIN NONCE ENGINE V1.1

SQLite-based persistent nonce management (BSC Mainnet / Chain ID 56).

Features:
- Cryptographically secure nonce generation
- Persistent nonce storage
- Atomic nonce consumption
- Replay attack protection
- Wallet-based nonce management
- Security audit integration
"""

import re
import secrets
import sqlite3
import time

from security.storage import VOINStorageEngine

DEFAULT_CHAIN_ID = 56
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_NONCE_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,128}$")
_ZERO_ADDRESS = "0x" + ("0" * 40)


class VOINNonceEngine:

    VERSION = "1.1.0"

    def __init__(self, storage=None):

        self.storage = storage or VOINStorageEngine()

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

    @staticmethod
    def _normalize_wallet(wallet_address, *, allow_zero: bool = False) -> str:
        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        cleaned = wallet_address.strip()
        if not cleaned:
            raise ValueError("Empty wallet address")

        if not _EVM_ADDRESS_RE.match(cleaned):
            raise ValueError("Invalid EVM wallet address format")

        normalized = cleaned.lower()
        if not allow_zero and normalized == _ZERO_ADDRESS:
            raise ValueError("Zero address is not allowed")

        return normalized

    # Generate and persist nonce
    def generate_nonce(self, wallet_address):

        wallet = self._normalize_wallet(wallet_address)

        # Retry in the extremely unlikely event of a collision.
        for _ in range(3):

            nonce = secrets.token_hex(32).lower()

            timestamp = self._now_ts()

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

        if not isinstance(nonce, str):
            return False

        cleaned_nonce = nonce.strip()
        if not cleaned_nonce or not _NONCE_HEX_RE.match(cleaned_nonce):
            return False

        try:

            wallet = self._normalize_wallet(wallet_address)

            return bool(
                self.storage.consume_nonce(
                    wallet,
                    cleaned_nonce.lower()
                )
            )

        except (ValueError, TypeError):
            return False

    # Engine information
    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Nonce Engine",
            "version": cls.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "storage": "SQLite",
            "cryptographic_random_nonce": True,
            "persistent_nonce_storage": True,
            "atomic_consumption": True,
            "replay_protection": True,
            "restart_protection": True,
            "status": "MAINNET_READY"
        }
