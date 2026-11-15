"""
VOIN VERIFICATION ENGINE V1.2

Persistent wallet challenge and digital signature verification.

Features:
- SQLite persistent challenge retrieval
- Wallet address validation
- Digital signature verification
- Atomic challenge and nonce consumption
- Replay protection
- Atomic authentication persistence
"""

import re

from security.challenge import VOINChallengeEngine
from security.signatures import VOINSignatureEngine


class VOINVerificationEngine:

    VERSION = "1.2.0"

    NONCE_PATTERN = re.compile(
        r"^Nonce: ([a-fA-F0-9]{64})$",
        re.MULTILINE
    )

    def __init__(self, expiry_seconds=300, storage=None):

        self.challenge_engine = VOINChallengeEngine(
            expiry_seconds=expiry_seconds,
            storage=storage
        )

        self.signature_engine = VOINSignatureEngine

    def create_verification_challenge(self, wallet_address):

        if not self.signature_engine.validate_address(
            wallet_address
        ):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        return self.challenge_engine.create_challenge(
            wallet_address
        )

    def verify_wallet(
        self,
        challenge_id,
        wallet_address,
        signature
    ):

        # 1. Validate wallet address.
        if not self.signature_engine.validate_address(
            wallet_address
        ):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        # 2. Validate challenge ownership and expiration.
        if not self.challenge_engine.validate_challenge(
            challenge_id,
            wallet_address
        ):
            return {
                "success": False,
                "status": "INVALID_OR_EXPIRED_CHALLENGE"
            }

        # 3. Retrieve persistent challenge.
        challenge = self.challenge_engine.storage.get_challenge(
            challenge_id
        )

        if not challenge:
            return {
                "success": False,
                "status": "CHALLENGE_NOT_FOUND"
            }

        # 4. Extract nonce from the original challenge message.
        nonce_match = self.NONCE_PATTERN.search(
            challenge["message"]
        )

        if nonce_match is None:
            return {
                "success": False,
                "status": "INVALID_CHALLENGE_NONCE"
            }

        nonce = nonce_match.group(1)

        # 5. Verify digital signature.
        result = self.signature_engine.verify_signature(
            message=challenge["message"],
            signature=signature,
            expected_address=wallet_address
        )

        if not result["success"]:
            return {
                "success": False,
                "status": result["status"]
            }

        # 6. Atomically consume challenge and nonce.
        consumed = self.challenge_engine.storage.consume_authentication(
            challenge_id=challenge_id,
            wallet_address=wallet_address,
            nonce=nonce
        )

        if not consumed:
            return {
                "success": False,
                "status": "CHALLENGE_OR_NONCE_ALREADY_USED"
            }

        # 7. Authentication successful.
        return {
            "success": True,
            "status": "WALLET_VERIFIED",
            "wallet_address": result["signer"],
            "challenge_id": challenge_id,
            "engine": "VOIN Verification Engine",
            "version": self.VERSION
        }

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Verification Engine",
            "version": cls.VERSION,
            "challenge_verification": True,
            "signature_verification": True,
            "persistent_storage": True,
            "atomic_consumption": True,
            "nonce_consumption": True,
            "replay_protection": True,
            "status": "READY_FOR_TESTING"
        }
