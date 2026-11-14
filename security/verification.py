"""
VOIN VERIFICATION ENGINE V1.0

Integrates wallet challenge and digital signature verification.
"""

from security.challenge import VOINChallengeEngine
from security.signatures import VOINSignatureEngine


class VOINVerificationEngine:

    VERSION = "1.0.0"

    def __init__(self, expiry_seconds=300):
        self.challenge_engine = VOINChallengeEngine(
            expiry_seconds=expiry_seconds
        )
        self.signature_engine = VOINSignatureEngine

    def create_verification_challenge(self, wallet_address):

        if not self.signature_engine.validate_address(wallet_address):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        return self.challenge_engine.create_challenge(
            wallet_address
        )

    def verify_wallet(self, challenge_id, wallet_address, signature):

        if not self.signature_engine.validate_address(wallet_address):
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

        if not self.challenge_engine.consume_challenge(challenge_id):
            return {
                "success": False,
                "status": "CHALLENGE_ALREADY_USED"
            }

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
            "replay_protection": True,
            "status": "READY_FOR_TESTING"
        }
