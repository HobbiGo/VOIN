"""
VOIN CHALLENGE ENGINE V1.1

Secure challenge generation and validation.
Supports externally generated nonce integration.
"""

import secrets
import time
import hashlib
import re


class VOINChallengeEngine:

    VERSION = "1.1.0"

    def __init__(self, expiry_seconds=300):

        if not isinstance(expiry_seconds, int) or expiry_seconds <= 0:
            raise ValueError("Invalid expiry duration")

        self.expiry_seconds = expiry_seconds
        self.challenges = {}

    def create_challenge(self, wallet_address, nonce=None):

        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        if not wallet_address.strip():
            raise ValueError("Empty wallet address")

        if nonce is None:
            nonce = secrets.token_hex(32)

        if not isinstance(nonce, str):
            raise ValueError("Invalid nonce")

        if not re.fullmatch(r"[a-fA-F0-9]{64}", nonce):
            raise ValueError("Nonce must contain 64 hexadecimal characters")

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

        self.challenges[challenge_id] = {
            "wallet": wallet_address,
            "nonce": nonce,
            "message": message,
            "created_at": timestamp,
            "expires_at": expires_at,
            "used": False
        }

        return {
            "success": True,
            "challenge_id": challenge_id,
            "message": message,
            "nonce": nonce,
            "expires_at": expires_at
        }

    def validate_challenge(self, challenge_id, wallet_address):

        if not isinstance(wallet_address, str):
            return False

        challenge = self.challenges.get(challenge_id)

        if not challenge:
            return False

        if challenge["used"]:
            return False

        if challenge["wallet"].lower() != wallet_address.lower():
            return False

        if int(time.time()) >= challenge["expires_at"]:
            return False

        return True

    def consume_challenge(self, challenge_id):

        challenge = self.challenges.get(challenge_id)

        if not challenge:
            return False

        if challenge["used"]:
            return False

        if int(time.time()) >= challenge["expires_at"]:
            return False

        challenge["used"] = True

        return True

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Challenge Engine",
            "version": cls.VERSION,
            "nonce_integration": True,
            "expiration_protection": True,
            "replay_protection": True,
            "status": "READY_FOR_TESTING"
        }
