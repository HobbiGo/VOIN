"""
VOIN SECURITY INTEGRATION ENGINE V1.0

Integrates:
- Wallet Verification Engine
- Challenge Engine
- Nonce Engine
- Digital Signature Engine
- Replay Protection
"""

from security.verification import VOINVerificationEngine
from security.nonce import VOINNonceEngine


class VOINSecurityIntegration:

    VERSION = "1.0.0"

    def __init__(self, expiry_seconds=300):

        self.verification_engine = VOINVerificationEngine(
            expiry_seconds=expiry_seconds
        )

        self.nonce_engine = VOINNonceEngine()

        self.challenge_engine = (
            self.verification_engine.challenge_engine
        )

        self.signature_engine = (
            self.verification_engine.signature_engine
        )

    def create_authentication(self, wallet_address):

        if not self.signature_engine.validate_address(
            wallet_address
        ):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        nonce_result = self.nonce_engine.generate_nonce(
            wallet_address
        )

        if not nonce_result["success"]:
            return {
                "success": False,
                "status": "NONCE_GENERATION_FAILED"
            }

        challenge_result = self.challenge_engine.create_challenge(
            wallet_address,
            nonce=nonce_result["nonce"]
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
            "nonce": nonce_result["nonce"],
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

        challenge = self.challenge_engine.challenges.get(
            challenge_id
        )

        if not challenge:
            return {
                "success": False,
                "status": "CHALLENGE_NOT_FOUND"
            }

        nonce_record = self.nonce_engine.wallet_nonces.get(
            wallet_address.lower()
        )

        if not nonce_record:
            return {
                "success": False,
                "status": "NONCE_NOT_FOUND"
            }

        if nonce_record["used"]:
            return {
                "success": False,
                "status": "NONCE_ALREADY_USED"
            }

        if nonce_record["nonce"] != challenge["nonce"]:
            return {
                "success": False,
                "status": "NONCE_MISMATCH"
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

        # Consume challenge after successful signature verification.

        if not self.challenge_engine.consume_challenge(
            challenge_id
        ):
            return {
                "success": False,
                "status": "CHALLENGE_ALREADY_USED"
            }

        # Consume nonce to prevent replay.

        if not self.nonce_engine.verify_nonce(
            wallet_address,
            challenge["nonce"]
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
            "replay_protection": True,
            "status": "READY_FOR_TESTING"
        }
