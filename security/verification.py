"""
VOIN VERIFICATION ENGINE V1.2

Persistent wallet challenge and digital signature verification (BSC Mainnet / Chain ID 56).

Features:
- SQLite persistent challenge retrieval
- Wallet address validation & normalization
- Digital signature verification
- Atomic challenge and nonce consumption
- Replay protection
- Atomic authentication persistence
"""

import re

from security.challenge import VOINChallengeEngine
from security.signatures import VOINSignatureEngine

DEFAULT_CHAIN_ID = 56


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

    @staticmethod
    def _normalize_wallet(wallet_address):
        if not isinstance(wallet_address, str):
            return None
        cleaned = wallet_address.strip()
        if not cleaned:
            return None
        return cleaned.lower()

    @staticmethod
    def _normalize_challenge_id(challenge_id):
        if not isinstance(challenge_id, str):
            return None
        cleaned = challenge_id.strip()
        return cleaned if cleaned else None

    def create_verification_challenge(self, wallet_address):

        if not self.signature_engine.validate_address(
            wallet_address
        ):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        normalized_wallet = self._normalize_wallet(wallet_address)

        return self.challenge_engine.create_challenge(
            normalized_wallet
        )

    def verify_wallet(
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

        # 1. Validate and normalize wallet address.
        if not self.signature_engine.validate_address(
            wallet_address
        ):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        normalized_wallet = self._normalize_wallet(wallet_address)

        # 2. Validate challenge ownership and expiration.
        if not self.challenge_engine.validate_challenge(
            normalized_challenge_id,
            normalized_wallet
        ):
            return {
                "success": False,
                "status": "INVALID_OR_EXPIRED_CHALLENGE"
            }

        # 3. Retrieve persistent challenge.
        challenge = self.challenge_engine.storage.get_challenge(
            normalized_challenge_id
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

        nonce = nonce_match.group(1).lower()

        # 5. Verify digital signature.
        result = self.signature_engine.verify_signature(
            message=challenge["message"],
            signature=signature,
            expected_address=normalized_wallet
        )

        if not result["success"]:
            return {
                "success": False,
                "status": result["status"]
            }

        # 6. Atomically consume challenge and nonce.
        consumed = self.challenge_engine.storage.consume_authentication(
            challenge_id=normalized_challenge_id,
            wallet_address=normalized_wallet,
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
            "normalized_wallet_address": result["signer"].lower(),
            "challenge_id": normalized_challenge_id,
            "engine": "VOIN Verification Engine",
            "version": self.VERSION
        }

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Verification Engine",
            "version": cls.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "challenge_verification": True,
            "signature_verification": True,
            "persistent_storage": True,
            "atomic_consumption": True,
            "nonce_consumption": True,
            "replay_protection": True,
            "status": "MAINNET_READY"
        }
