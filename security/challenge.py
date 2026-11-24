"""
VOIN CHALLENGE ENGINE V1.3.1

Features:
- Secure nonce generation
- Challenge ID generation
- Wallet validation & normalization
- Nonce format validation
- Atomic nonce and challenge persistence
- Challenge expiration
- Wallet ownership validation
- Replay protection
- Persistent challenge storage
"""

import hashlib
import re
import secrets
import time

from security.storage import VOINStorageEngine

DEFAULT_CHAIN_ID = 56
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = "0x" + ("0" * 40)


class VOINChallengeEngine:

    VERSION = "1.3.1"

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

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

    @staticmethod
    def _normalize_wallet(wallet_address, *, allow_zero: bool = False) -> str:
        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        cleaned = wallet_address.strip()
        if not cleaned:
            raise ValueError("Invalid wallet address")

        if not _EVM_ADDRESS_RE.match(cleaned):
            raise ValueError("Invalid EVM wallet address format")

        normalized = cleaned.lower()
        if not allow_zero and normalized == _ZERO_ADDRESS:
            raise ValueError("Zero address is not allowed")

        return normalized

    @staticmethod
    def _normalize_challenge_id(challenge_id):
        if not isinstance(challenge_id, str):
            return None
        cleaned = challenge_id.strip()
        return cleaned if cleaned else None

    # ==================================================
    # CREATE CHALLENGE
    # ==================================================

    def create_challenge(
        self,
        wallet_address,
        nonce=None
    ):

        normalized_wallet = self._normalize_wallet(wallet_address)

        if nonce is None:
            nonce = secrets.token_hex(32)
        elif isinstance(nonce, str):
            nonce = nonce.strip()

        if (
            not isinstance(nonce, str)
            or not self.NONCE_PATTERN.fullmatch(nonce)
        ):
            raise ValueError("Invalid nonce format")

        normalized_nonce = nonce.lower()

        timestamp = self._now_ts()

        expires_at = (
            timestamp + self.expiry_seconds
        )

        challenge_id = hashlib.sha256(
            secrets.token_bytes(32)
        ).hexdigest()

        message = (
            "VOIN WALLET AUTHENTICATION\n"
            f"Wallet: {normalized_wallet}\n"
            f"Nonce: {normalized_nonce}\n"
            f"Timestamp: {timestamp}\n"
            f"Challenge ID: {challenge_id}\n"
            "Purpose: Wallet ownership verification"
        )

        # IMPORTANT:
        # Parameter order must match Storage V1.4.0:
        # challenge_id, wallet_address, nonce,
        # message, expires_at.

        self.storage.create_challenge_atomic(
            challenge_id,
            normalized_wallet,
            normalized_nonce,
            message,
            expires_at
        )

        return {
            "success": True,
            "challenge_id": challenge_id,
            "message": message,
            "nonce": normalized_nonce,
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

        normalized_challenge_id = self._normalize_challenge_id(
            challenge_id
        )
        if normalized_challenge_id is None:
            return False

        try:
            normalized_wallet = self._normalize_wallet(wallet_address)
        except ValueError:
            return False

        try:

            challenge = self.storage.get_challenge(
                normalized_challenge_id
            )

            if not challenge:
                return False

            if challenge.get("used"):
                return False

            stored_wallet = challenge.get(
                "wallet_address"
            )

            if not isinstance(stored_wallet, str):
                return False

            if (
                stored_wallet.strip().lower()
                != normalized_wallet
            ):
                return False

            expires_at = challenge.get("expires_at")

            if (
                isinstance(expires_at, bool)
                or not isinstance(expires_at, int)
            ):
                return False

            if self._now_ts() >= expires_at:
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

        normalized_challenge_id = self._normalize_challenge_id(
            challenge_id
        )
        if normalized_challenge_id is None:
            return False

        try:

            if wallet_address is None:

                challenge = self.storage.get_challenge(
                    normalized_challenge_id
                )

                if not challenge:
                    return False

                wallet_address = challenge.get(
                    "wallet_address"
                )

            normalized_wallet = self._normalize_wallet(wallet_address)

            return self.storage.consume_challenge(
                normalized_challenge_id,
                normalized_wallet
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
            "chain_id": DEFAULT_CHAIN_ID,
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
            "status": "MAINNET_READY"
        }
