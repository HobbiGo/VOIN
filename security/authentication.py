"""
VOIN AUTHENTICATION ENGINE V1.1

Persistent wallet authentication (BSC Mainnet / Chain ID 56).

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

DEFAULT_CHAIN_ID = 56
DEFAULT_NETWORK = "BSC_MAINNET"


class VOINAuthenticationEngine:

    VERSION = "1.1.0"

    NONCE_PATTERN = re.compile(
        r"^Nonce: ([a-fA-F0-9]{64})$",
        re.MULTILINE
    )

    def __init__(
        self,
        expiry_seconds=300,
        network=DEFAULT_NETWORK,
        chain_id=DEFAULT_CHAIN_ID
    ):

        if (
            isinstance(expiry_seconds, bool)
            or not isinstance(expiry_seconds, (int, float))
            or expiry_seconds <= 0
        ):
            raise ValueError("Invalid expiry_seconds")

        if (
            isinstance(chain_id, bool)
            or not isinstance(chain_id, int)
            or chain_id <= 0
        ):
            raise ValueError("Invalid chain_id")

        if not isinstance(network, str) or not network.strip():
            raise ValueError("Invalid network")

        self.identity_engine = VOINIdentity()

        self.challenge_engine = VOINChallengeEngine(
            expiry_seconds=expiry_seconds
        )

        # Share the same SQLite storage.
        self.nonce_engine = VOINNonceEngine(
            storage=self.challenge_engine.storage
        )

        self.signature_engine = VOINSignatureEngine

        self.network = network.strip().upper()
        self.chain_id = chain_id

        self.identities = {}

    @staticmethod
    def _normalize_wallet(wallet_address):
        if not isinstance(wallet_address, str):
            return None
        cleaned = wallet_address.strip()
        return cleaned.lower() if cleaned else None

    @staticmethod
    def _normalize_challenge_id(challenge_id):
        if not isinstance(challenge_id, str):
            return None
        cleaned = challenge_id.strip()
        return cleaned if cleaned else None

    # Create authentication challenge
    def create_authentication_challenge(self, wallet_address):

        if not self.signature_engine.validate_address(wallet_address):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        wallet = self._normalize_wallet(wallet_address)

        if wallet not in self.identities:

            identity = self.identity_engine.create_identity(
                wallet,
                network=self.network
            )

            self.identities[wallet] = identity

        identity = self.identities[wallet]

        # Challenge Engine generates and registers
        # the nonce exactly once.
        challenge = self.challenge_engine.create_challenge(
            wallet
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
            "expires_at": challenge["expires_at"],
            "chain_id": self.chain_id,
            "network": self.network,
        }

    # Verify wallet authentication
    def authenticate_wallet(
        self,
        challenge_id,
        wallet_address,
        signature
    ):

        normalized_challenge_id = self._normalize_challenge_id(
            challenge_id
        )
        if normalized_challenge_id is None:
            return {
                "success": False,
                "status": "INVALID_OR_EXPIRED_CHALLENGE"
            }

        if not self.signature_engine.validate_address(wallet_address):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        wallet = self._normalize_wallet(wallet_address)

        identity = self.identities.get(wallet)

        if not identity:
            return {
                "success": False,
                "status": "IDENTITY_NOT_FOUND"
            }

        if identity.get("status") != "ACTIVE":
            return {
                "success": False,
                "status": "IDENTITY_INACTIVE"
            }

        if not self.identity_engine.validate_wallet_address(wallet):
            return {
                "success": False,
                "status": "INVALID_IDENTITY"
            }

        if not self.challenge_engine.validate_challenge(
            normalized_challenge_id,
            wallet
        ):
            return {
                "success": False,
                "status": "INVALID_OR_EXPIRED_CHALLENGE"
            }

        # Retrieve challenge from SQLite.
        challenge = self.challenge_engine.storage.get_challenge(
            normalized_challenge_id
        )

        if not challenge:
            return {
                "success": False,
                "status": "CHALLENGE_NOT_FOUND"
            }

        # Extract nonce from the stored challenge message.
        match = self.NONCE_PATTERN.search(
            challenge["message"]
        )

        if not match:
            return {
                "success": False,
                "status": "INVALID_CHALLENGE_NONCE"
            }

        nonce = match.group(1).lower()

        # Verify digital signature first.
        signature_result = self.signature_engine.verify_signature(
            message=challenge["message"],
            signature=signature,
            expected_address=wallet
        )

        if not signature_result["success"]:
            return {
                "success": False,
                "status": signature_result["status"]
            }

        # Atomically consume challenge and nonce when supported.
        storage = getattr(self.challenge_engine, "storage", None)
        consume_auth = getattr(storage, "consume_authentication", None)

        if callable(consume_auth):
            if not consume_auth(
                challenge_id=normalized_challenge_id,
                wallet_address=wallet,
                nonce=nonce
            ):
                return {
                    "success": False,
                    "status": "CHALLENGE_OR_NONCE_ALREADY_USED"
                }
        else:
            if not self.challenge_engine.consume_challenge(
                normalized_challenge_id,
                wallet
            ):
                return {
                    "success": False,
                    "status": "CHALLENGE_ALREADY_USED"
                }

            if not self.nonce_engine.verify_nonce(
                wallet,
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
            "normalized_wallet_address": signature_result["signer"].lower(),
            "identity_id": identity["identity_id"],
            "challenge_id": normalized_challenge_id,
            "chain_id": self.chain_id,
            "network": identity.get("network", self.network),
            "engine": "VOIN Authentication Engine",
            "version": self.VERSION
        }

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Authentication Engine",
            "version": cls.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "network": DEFAULT_NETWORK,
            "wallet_identity": True,
            "challenge_verification": True,
            "nonce_protection": True,
            "digital_signature": True,
            "persistent_storage": True,
            "replay_protection": True,
            "status": "MAINNET_READY"
        }
