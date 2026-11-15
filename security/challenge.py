"""
VOIN CHALLENGE ENGINE V1.3.0

Features:
- Secure nonce generation
- Challenge ID generation
- Wallet validation
- Nonce format validation
- Atomic nonce and challenge persistence
- Challenge expiration
- Wallet ownership validation
- Replay protection
- Persistent challenge storage
"""

import secrets
import time
import hashlib
import re

from security.storage import VOINStorageEngine


class VOINChallengeEngine:

    VERSION = "1.3.0"

    NONCE_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

    def __init__(
        self,
        expiry_seconds=300,
        storage=None
    ):

        if (
            isinstance(expiry_seconds, bool)
            or not isinstance(expiry_seconds, int)
            or expiry_seconds <= 0
        ):
            raise ValueError(
                "expiry_seconds must be a positive integer"
            )

        self.expiry_seconds = expiry_seconds

        self.storage = (
            storage
            if storage is not None
            else VOINStorageEngine()
        )

    # ==================================================
    # CREATE CHALLENGE
    # ==================================================

    def create_challenge(
        self,
        wallet_address,
        nonce=None
    ):

        if (
            not isinstance(wallet_address, str)
            or not wallet_address.strip()
        ):
            raise ValueError("Invalid wallet address")

        wallet_address = wallet_address.strip()

        # Generate secure nonce.
        if nonce is None:
            nonce = secrets.token_hex(32)

        if (
            not isinstance(nonce, str)
            or not self.NONCE_PATTERN.fullmatch(nonce)
        ):
            raise ValueError("Invalid nonce format")

        # Generate timestamp.
        timestamp = int(time.time())

        expires_at = (
            timestamp + self.expiry_seconds
        )

        # Generate unique challenge ID.
        challenge_id = hashlib.sha256(
            secrets.token_bytes(32)
        ).hexdigest()

        # EIP-191 compatible message.
        message = (
            "VOIN WALLET AUTHENTICATION\n"
            f"Wallet: {wallet_address}\n"
            f"Nonce: {nonce}\n"
            f"Timestamp: {timestamp}\n"
            f"Challenge ID: {challenge_id}\n"
            "Purpose: Wallet ownership verification"
        )

        # ATOMIC STORAGE:
        # Nonce, challenge and security events
        # must be committed in one transaction.
        self.storage.create_challenge_atomic(
            wallet_address,
            challenge_id,
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

    # ==================================================
    # VALIDATE CHALLENGE
    # ==================================================

    def validate_challenge(
        self,
        challenge_id,
        wallet_address
    ):

        if (
            not isinstance(challenge_id, str)
            or not isinstance(wallet_address, str)
        ):
            return False

        if not challenge_id or not wallet_address.strip():
            return False

        try:

            challenge = self.storage.get_challenge(
                challenge_id
            )

            if not challenge:
                return False

            if challenge.get("used"):
                return False

            stored_wallet = challenge.get("wallet")

            if not isinstance(stored_wallet, str):
                return False

            if (
                stored_wallet.strip().lower()
                != wallet_address.strip().lower()
            ):
                return False

            expires_at = challenge.get("expires_at")

            if (
                isinstance(expires_at, bool)
                or not isinstance(expires_at, int)
            ):
                return False

            if int(time.time()) >= expires_at:
                return False

            return True

        except (ValueError, TypeError):
            return False

    # ==================================================
    # CONSUME CHALLENGE
    # ==================================================

    def consume_challenge(
        self,
        challenge_id,
        wallet_address=None
    ):

        if not isinstance(challenge_id, str):
            return False

        if wallet_address is not None:

            if not isinstance(wallet_address, str):
                return False

        try:

            return self.storage.consume_challenge(
                challenge_id,
                wallet_address
            )

        except (ValueError, TypeError):
            return False

    # ==================================================
    # ENGINE INFORMATION
    # ==================================================

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Challenge Engine",
            "version": cls.VERSION,
            "storage": "SQLite",
            "persistent_challenges": True,
            "persistent_nonces": True,
            "secure_nonce_generation": True,
            "nonce_validation": True,
            "atomic_challenge_creation": True,
            "challenge_expiration": True,
            "wallet_ownership_validation": True,
            "atomic_consumption": True,
            "replay_protection": True,
            "status": "READY_FOR_TESTING"
        }
