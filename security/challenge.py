"""
VOIN CHALLENGE ENGINE V1.0

Secure challenge generation and validation.
"""

import secrets
import time
import hashlib


class VOINChallengeEngine:

    VERSION = "1.0.0"

    def __init__(self, expiry_seconds=300):

        self.expiry_seconds = expiry_seconds
        self.challenges = {}

    # Generate secure challenge
    def create_challenge(self, wallet_address):

        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        nonce = secrets.token_hex(32)

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

        self.challenges[challenge_id] = {
            "wallet": wallet_address,
            "nonce": nonce,
            "message": message,
            "created_at": timestamp,
            "expires_at": timestamp + self.expiry_seconds,
            "used": False
        }

        return {
            "success": True,
            "challenge_id": challenge_id,
            "message": message,
            "expires_at": timestamp + self.expiry_seconds
        }

    # Validate challenge
    def validate_challenge(self, challenge_id, wallet_address):

        challenge = self.challenges.get(challenge_id)

        if not challenge:
            return False

        if challenge["used"]:
            return False

        if challenge["wallet"].lower() != wallet_address.lower():
            return False

        if int(time.time()) > challenge["expires_at"]:
            return False

        return True

    # Consume challenge
    def consume_challenge(self, challenge_id):

        challenge = self.challenges.get(challenge_id)

        if not challenge:
            return False

        if challenge["used"]:
            return False

        if int(time.time()) > challenge["expires_at"]:
            return False

        challenge["used"] = True

        return True

    # Engine information
    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Challenge Engine",
            "version": cls.VERSION,
            "nonce_security": True,
            "expiration_protection": True,
            "replay_protection": True,
            "status": "READY_FOR_TESTING"
        }
