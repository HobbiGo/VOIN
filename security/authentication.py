"""
VOIN AUTHENTICATION ENGINE V1.0

Integrates wallet identity, challenge,
nonce and digital signature verification.
"""

from wallet.identity import VOINIdentity
from security.challenge import VOINChallengeEngine
from security.nonce import VOINNonceEngine
from security.signatures import VOINSignatureEngine


class VOINAuthenticationEngine:

    VERSION = "1.0.0"

    def __init__(self, expiry_seconds=300, network="BSC"):

        self.identity_engine = VOINIdentity()
        self.challenge_engine = VOINChallengeEngine(
            expiry_seconds=expiry_seconds
        )
        self.nonce_engine = VOINNonceEngine()

        self.signature_engine = VOINSignatureEngine
        self.network = network

        self.identities = {}

    # Create authentication challenge
    def create_authentication_challenge(self, wallet_address):

        if not self.signature_engine.validate_address(wallet_address):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        wallet = wallet_address.lower()

        if wallet not in self.identities:

            identity = self.identity_engine.create_identity(
                wallet_address,
                network=self.network
            )

            self.identities[wallet] = identity

        identity = self.identities[wallet]

        nonce_result = self.nonce_engine.generate_nonce(
            wallet_address
        )

        challenge = self.challenge_engine.create_challenge(
            wallet_address,
            nonce=nonce_result["nonce"]
        )

        return {
            "success": True,
            "status": "CHALLENGE_CREATED",
            "identity": identity,
            "challenge_id": challenge["challenge_id"],
            "message": challenge["message"],
            "nonce": challenge["nonce"],
            "expires_at": challenge["expires_at"]
        }

    # Verify wallet authentication
    def authenticate_wallet(
        self,
        challenge_id,
        wallet_address,
        signature
    ):

        if not self.signature_engine.validate_address(wallet_address):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        wallet = wallet_address.lower()

        identity = self.identities.get(wallet)

        if not identity:
            return {
                "success": False,
                "status": "IDENTITY_NOT_FOUND"
            }

        if identity["status"] != "ACTIVE":
            return {
                "success": False,
                "status": "IDENTITY_INACTIVE"
            }

        if not self.identity_engine.validate_wallet_address(wallet_address):
            return {
                "success": False,
                "status": "INVALID_IDENTITY"
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

        signature_result = self.signature_engine.verify_signature(
            message=challenge["message"],
            signature=signature,
            expected_address=wallet_address
        )

        if not signature_result["success"]:
            return {
                "success": False,
                "status": signature_result["status"]
            }

        nonce_valid = self.nonce_engine.verify_nonce(
            wallet_address,
            challenge["nonce"]
        )

        if not nonce_valid:
            return {
                "success": False,
                "status": "INVALID_OR_USED_NONCE"
            }

        if not self.challenge_engine.consume_challenge(challenge_id):
            return {
                "success": False,
                "status": "CHALLENGE_ALREADY_USED"
            }

        return {
            "success": True,
            "status": "AUTHENTICATION_VERIFIED",
            "wallet_address": signature_result["signer"],
            "identity_id": identity["identity_id"],
            "challenge_id": challenge_id,
            "network": identity["network"],
            "engine": "VOIN Authentication Engine",
            "version": self.VERSION
        }

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Authentication Engine",
            "version": cls.VERSION,
            "wallet_identity": True,
            "challenge_verification": True,
            "nonce_protection": True,
            "digital_signature": True,
            "status": "READY_FOR_TESTING"
        }
