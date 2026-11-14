"""
VOIN AUTHENTICATION ENGINE V1.1

Persistent wallet authentication.

Features:
- Wallet identity verification
- SQLite challenge storage
- Persistent nonce management
- Digital signature verification
- Replay attack protection
"""

import re

from wallet.identity import VOINIdentity
from security.challenge import VOINChallengeEngine
from security.nonce import VOINNonceEngine
from security.signatures import VOINSignatureEngine


class VOINAuthenticationEngine:

    VERSION = "1.1.0"

    def __init__(self, expiry_seconds=300, network="BSC"):

        self.identity_engine = VOINIdentity()

        self.challenge_engine = VOINChallengeEngine(
            expiry_seconds=expiry_seconds
        )

        # Share the same SQLite storage.
        self.nonce_engine = VOINNonceEngine(
            storage=self.challenge_engine.storage
        )

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

        # Challenge Engine generates and registers
        # the nonce exactly once.
        challenge = self.challenge_engine.create_challenge(
            wallet_address
        )

        if not challenge["success"]:
            return {
                "success": False,
                "status": "CHALLENGE_GENERATION_FAILED"
            }

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

        # Retrieve challenge from SQLite.
        challenge = self.challenge_engine.storage.get_challenge(
            challenge_id
        )

        if not challenge:
            return {
                "success": False,
                "status": "CHALLENGE_NOT_FOUND"
            }

        # Extract nonce from the stored challenge message.
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

        # Verify digital signature first.
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

        # Consume challenge.
        if not self.challenge_engine.consume_challenge(
            challenge_id,
            wallet_address
        ):
            return {
                "success": False,
                "status": "CHALLENGE_ALREADY_USED"
            }

        # Consume associated nonce.
        if not self.nonce_engine.verify_nonce(
            wallet_address,
            nonce
        ):
            return {
                "success": False,
                "status": "INVALID_OR_USED_NONCE"
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
            "persistent_storage": True,
            "replay_protection": True,
            "status": "READY_FOR_TESTING"
        }
