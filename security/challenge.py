"""
VOIN CHALLENGE ENGINE V1.2

SQLite persistent challenge generation and validation.

Features:
- Persistent challenge storage
- Persistent nonce registration
- Challenge expiration protection
- Atomic challenge consumption
- Replay protection
- Security audit integration
"""

import secrets
import time
import hashlib
import re

from security.storage import VOINStorageEngine


class VOINChallengeEngine:

    VERSION = "1.2.0"

    def __init__(
        self,
        expiry_seconds=300,
        storage=None
    ):

        if (
            not isinstance(expiry_seconds, int)
            or isinstance(expiry_seconds, bool)
            or expiry_seconds <= 0
        ):
            raise ValueError("Invalid expiry duration")

        self.expiry_seconds = expiry_seconds

        self.storage = storage or VOINStorageEngine()

    def create_challenge(self, wallet_address, nonce=None):

        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        wallet_address = wallet_address.strip()

        if not wallet_address:
            raise ValueError("Empty wallet address")

        if nonce is None:
            nonce = secrets.token_hex(32)

        if not isinstance(nonce, str):
            raise ValueError("Invalid nonce")

        if not re.fullmatch(r"[a-fA-F0-9]{64}", nonce):
            raise ValueError(
                "Nonce must contain 64 hexadecimal characters"
            )

        timestamp = int(time.time())

        challenge_id = hashlib.sha256(
            secrets.token_bytes(32)
        ).hexdigest()

        message = (
            "VOIN WALLET AUTHENTICATION\n"
            f"Wallet: {wallet_address}\n"
            f"Nonce: {nonce}\n"
            f"Timestamp: {timestamp}\n"
            f"Challenge ID: {challenge_id}\n"
            "Purpose: Wallet ownership verification"
        )

        expires_at = timestamp + self.expiry_seconds

        # Register nonce permanently.
        self.storage.save_nonce(
            wallet_address,
            nonce
        )

        # Persist challenge in SQLite.
        self.storage.save_challenge(
            challenge_id,
            wallet_address,
            nonce,
            message,
            expires_at
        )

        return {
            "success": True,
            "challenge_id": challenge_id,
            "message": message,
            "nonce": nonce,
            "expires_at": expires_at
        }

    def validate_challenge(
        self,
        challenge_id,
        wallet_address
    ):

        if not isinstance(challenge_id, str):
            return False

        if not isinstance(wallet_address, str):
            return False

        try:

            challenge = self.storage.get_challenge(
                challenge_id
            )

            if not challenge:
                return False

            if challenge["used"]:
                return False

            if (
                challenge["wallet_address"].lower()
                != wallet_address.strip().lower()
            ):
                return False

            if int(time.time()) >= challenge["expires_at"]:
                return False

            return True

        except (ValueError, TypeError):
            return False

    def consume_challenge(
        self,
        challenge_id,
        wallet_address=None
    ):

        if not isinstance(challenge_id, str):
            return False

        if not isinstance(wallet_address, str):
            return False

        try:

            return self.storage.consume_challenge(
                challenge_id,
                wallet_address
            )

        except (ValueError, TypeError):
            return False

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Challenge Engine",
            "version": cls.VERSION,
            "storage": "SQLite",
            "persistent_challenges": True,
            "persistent_nonces": True,
            "expiration_protection": True,
            "atomic_consumption": True,
            "replay_protection": True,
            "status": "READY_FOR_TESTING"
        }
