"""
VOIN SECURITY INTEGRATION ENGINE V1.1

Integrates:
- Wallet Verification Engine
- Persistent Challenge Engine
- Persistent Nonce Engine
- Digital Signature Engine
- SQLite Storage
- Replay Protection
"""

import re

from security.verification import VOINVerificationEngine
from security.nonce import VOINNonceEngine


class VOINSecurityIntegration:

    VERSION = "1.1.0"

    def __init__(self, expiry_seconds=300):

        self.verification_engine = VOINVerificationEngine(
            expiry_seconds=expiry_seconds
        )

        self.challenge_engine = (
            self.verification_engine.challenge_engine
        )

        self.signature_engine = (
            self.verification_engine.signature_engine
        )

        # Share the same persistent SQLite storage.
        self.nonce_engine = VOINNonceEngine(
            storage=self.challenge_engine.storage
        )

    def create_authentication(self, wallet_address):

        if not self.signature_engine.validate_address(
            wallet_address
        ):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        # Challenge Engine generates and registers
        # the nonce exactly once in SQLite.
        challenge_result = self.challenge_engine.create_challenge(
            wallet_address
        )

        if not challenge_result["success"]:
            return {
                "success": False,
                "status": "CHALLENGE_GENERATION_FAILED"
            }

        return {
            "success": True,
            "status": "AUTHENTICATION_CHALLENGE_CREATED",
            "wallet_address": wallet_address,
            "challenge_id": challenge_result["challenge_id"],
            "message": challenge_result["message"],
            "nonce": challenge_result["nonce"],
            "expires_at": challenge_result["expires_at"],
            "engine": "VOIN Security Integration",
            "version": self.VERSION
        }

    def verify_authentication(
        self,
        challenge_id,
        wallet_address,
        signature
    ):

        if not self.signature_engine.validate_address(
            wallet_address
        ):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        if not self.challenge_engine.validate_challenge(
            challenge_id,
            wallet_address
        ):
            return {
                "success": False,
                "status": "INVALID_OR_EXPIRED_CHALLENGE"
            }

        # Retrieve challenge from persistent SQLite storage.
        challenge = self.challenge_engine.storage.get_challenge(
            challenge_id
        )

        if not challenge:
            return {
                "success": False,
                "status": "CHALLENGE_NOT_FOUND"
            }

        # Extract nonce from the signed challenge message.
        match = re.search(
            r"^Nonce: ([a-fA-F0-9]{64})$",
            challenge["message"],
            re.MULTILINE
        )

        if not match:
            return {
                "success": False,
                "status": "INVALID_CHALLENGE_NONCE"
            }

        nonce = match.group(1)

        # Verify digital signature.
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

        # Atomically consume challenge.
        if not self.challenge_engine.consume_challenge(
            challenge_id,
            wallet_address
        ):
            return {
                "success": False,
                "status": "CHALLENGE_ALREADY_USED"
            }

        # Atomically consume the associated nonce.
        if not self.nonce_engine.verify_nonce(
            wallet_address,
            nonce
        ):
            return {
                "success": False,
                "status": "NONCE_VERIFICATION_FAILED"
            }

        return {
            "success": True,
            "status": "AUTHENTICATION_SUCCESSFUL",
            "wallet_address": result["signer"],
            "challenge_id": challenge_id,
            "engine": "VOIN Security Integration",
            "version": self.VERSION
        }

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Security Integration",
            "version": cls.VERSION,
            "wallet_verification": True,
            "challenge_validation": True,
            "digital_signature": True,
            "nonce_protection": True,
            "persistent_storage": True,
            "replay_protection": True,
            "status": "READY_FOR_TESTING"
        }
