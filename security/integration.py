"""
VOIN SECURITY INTEGRATION ENGINE V1.2

Integrates:
- Wallet Verification Engine
- Persistent Challenge Engine
- Persistent Nonce Engine
- Digital Signature Engine
- SQLite Storage
- Replay Protection
"""

import re
import hashlib

from security.verification import VOINVerificationEngine
from security.nonce import VOINNonceEngine


class VOINSecurityIntegration:

    VERSION = "1.2.0"

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

        challenge = self.challenge_engine.storage.get_challenge(
            challenge_id
        )

        if not challenge:
            return {
                "success": False,
                "status": "CHALLENGE_NOT_FOUND"
            }

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

        # Verify the nonce record before signature verification.
        nonce_hash = hashlib.sha256(
            nonce.encode()
        ).hexdigest()

        with self.challenge_engine.storage._connect() as connection:

            nonce_record = connection.execute(
                """
                SELECT used
                FROM nonces
                WHERE wallet_address = ?
                AND nonce_hash = ?
                """,
                (
                    wallet_address.lower(),
                    nonce_hash
                )
            ).fetchone()

        if nonce_record is None:
            return {
                "success": False,
                "status": "NONCE_MISMATCH"
            }

        if nonce_record[0] == 1:
            return {
                "success": False,
                "status": "NONCE_ALREADY_USED"
            }

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

        if not self.challenge_engine.consume_challenge(
            challenge_id,
            wallet_address
        ):
            return {
                "success": False,
                "status": "CHALLENGE_ALREADY_USED"
            }

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
