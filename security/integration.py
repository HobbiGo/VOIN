"""
VOIN SECURITY INTEGRATION ENGINE V1.5.0 (BSC Mainnet / Chain ID 56)
"""

import re
import time

from security.audit import VOINAuditEngine
from security.nonce import VOINNonceEngine
from security.rate_limit import VOINRateLimitEngine
from security.verification import VOINVerificationEngine

DEFAULT_CHAIN_ID = 56


class VOINSecurityIntegration:
    VERSION = "1.5.0"

    def __init__(
        self,
        expiry_seconds=300,
        max_attempts=5,
        window_seconds=300,
        cooldown_seconds=300
    ):
        self.verification_engine = VOINVerificationEngine(
            expiry_seconds=expiry_seconds
        )

        self.challenge_engine = (
            self.verification_engine.challenge_engine
        )

        self.signature_engine = (
            self.verification_engine.signature_engine
        )

        storage = self.challenge_engine.storage

        self.nonce_engine = VOINNonceEngine(
            storage=storage
        )

        self.audit_engine = VOINAuditEngine(
            storage=storage
        )

        self.rate_limit_engine = VOINRateLimitEngine(
            storage=storage,
            max_attempts=max_attempts,
            window_seconds=window_seconds,
            cooldown_seconds=cooldown_seconds
        )

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

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

    def _audit_failure(
        self,
        wallet_address=None,
        challenge_id=None,
        reason="AUTHENTICATION_FAILED"
    ):
        normalized_wallet = self._normalize_wallet(wallet_address)
        normalized_challenge_id = self._normalize_challenge_id(challenge_id)

        self.audit_engine.record_authentication_failure(
            wallet_address=normalized_wallet,
            challenge_id=normalized_challenge_id,
            reason=reason
        )

    def create_authentication(self, wallet_address):
        if not self.signature_engine.validate_address(
            wallet_address
        ):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        normalized_wallet = self._normalize_wallet(wallet_address)

        challenge_result = self.challenge_engine.create_challenge(
            normalized_wallet
        )

        if not challenge_result["success"]:
            self._audit_failure(
                wallet_address=normalized_wallet,
                reason="CHALLENGE_GENERATION_FAILED"
            )

            return {
                "success": False,
                "status": "CHALLENGE_GENERATION_FAILED"
            }

        return {
            "success": True,
            "status": "AUTHENTICATION_CHALLENGE_CREATED",
            "wallet_address": normalized_wallet,
            "chain_id": DEFAULT_CHAIN_ID,
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
            self._audit_failure(
                reason="INVALID_ADDRESS"
            )

            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        normalized_wallet = self._normalize_wallet(wallet_address)
        normalized_challenge_id = self._normalize_challenge_id(challenge_id)

        # RATE LIMITING CHECK
        rate_result = self.rate_limit_engine.consume_attempt(
            normalized_wallet
        )

        if not rate_result["allowed"]:
            return {
                "success": False,
                "status": "RATE_LIMIT_EXCEEDED",
                "wallet_address": normalized_wallet,
                "attempts": rate_result["attempts"],
                "remaining": 0,
                "retry_after": rate_result["retry_after"]
            }

        storage = self.challenge_engine.storage

        if normalized_challenge_id is None:
            self.audit_engine.record_event(
                event_type="INVALID_CHALLENGE",
                wallet_address=normalized_wallet,
                reference_id=None,
                details={
                    "result": "REJECTED"
                }
            )

            return {
                "success": False,
                "status": "INVALID_OR_EXPIRED_CHALLENGE"
            }

        # CHALLENGE VALIDATION
        if not self.challenge_engine.validate_challenge(
            normalized_challenge_id,
            normalized_wallet
        ):
            challenge = storage.get_challenge(normalized_challenge_id)

            if challenge:
                if challenge.get("used") == 1:
                    self.audit_engine.record_replay_attempt(
                        normalized_wallet,
                        normalized_challenge_id
                    )

                    return {
                        "success": False,
                        "status": "CHALLENGE_ALREADY_USED"
                    }

                if challenge.get("expires_at", 0) <= self._now_ts():
                    self.audit_engine.record_event(
                        event_type="EXPIRED_CHALLENGE",
                        wallet_address=normalized_wallet,
                        reference_id=normalized_challenge_id,
                        details={
                            "result": "REJECTED"
                        }
                    )

                    return {
                        "success": False,
                        "status": "INVALID_OR_EXPIRED_CHALLENGE"
                    }

            self.audit_engine.record_event(
                event_type="INVALID_CHALLENGE",
                wallet_address=normalized_wallet,
                reference_id=normalized_challenge_id,
                details={
                    "result": "REJECTED"
                }
            )

            return {
                "success": False,
                "status": "INVALID_OR_EXPIRED_CHALLENGE"
            }

        challenge = storage.get_challenge(normalized_challenge_id)

        if not challenge:
            self._audit_failure(
                wallet_address=normalized_wallet,
                challenge_id=normalized_challenge_id,
                reason="CHALLENGE_NOT_FOUND"
            )

            return {
                "success": False,
                "status": "CHALLENGE_NOT_FOUND"
            }

        # NONCE FORMAT VALIDATION
        match = re.search(
            r"^Nonce: ([a-fA-F0-9]{64})$",
            challenge["message"],
            re.MULTILINE
        )

        if not match:
            self.audit_engine.record_event(
                event_type="INVALID_NONCE",
                wallet_address=normalized_wallet,
                reference_id=normalized_challenge_id,
                details={
                    "result": "REJECTED",
                    "reason": "INVALID_NONCE_FORMAT"
                }
            )

            return {
                "success": False,
                "status": "INVALID_CHALLENGE_NONCE"
            }

        nonce = match.group(1).lower()

        # DIGITAL SIGNATURE VERIFICATION
        result = self.signature_engine.verify_signature(
            message=challenge["message"],
            signature=signature,
            expected_address=normalized_wallet
        )

        if not result["success"]:
            self._audit_failure(
                wallet_address=normalized_wallet,
                challenge_id=normalized_challenge_id,
                reason=result["status"]
            )

            return {
                "success": False,
                "status": result["status"]
            }

        # ATOMIC AUTHENTICATION CONSUMPTION
        consumed = storage.consume_authentication(
            normalized_challenge_id,
            normalized_wallet,
            nonce
        )

        if not consumed:
            self._audit_failure(
                wallet_address=normalized_wallet,
                challenge_id=normalized_challenge_id,
                reason="AUTHENTICATION_CONSUMPTION_FAILED"
            )

            return {
                "success": False,
                "status": "AUTHENTICATION_CONSUMPTION_FAILED"
            }

        # AUTHENTICATION SUCCESS AUDIT
        self.audit_engine.record_authentication_success(
            wallet_address=normalized_wallet,
            challenge_id=normalized_challenge_id
        )

        return {
            "success": True,
            "status": "AUTHENTICATION_SUCCESSFUL",
            "wallet_address": result["signer"].lower(),
            "chain_id": DEFAULT_CHAIN_ID,
            "challenge_id": normalized_challenge_id,
            "engine": "VOIN Security Integration",
            "version": self.VERSION
        }

    @classmethod
    def engine_info(cls):
        return {
            "engine": "VOIN Security Integration",
            "version": cls.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "wallet_verification": True,
            "challenge_validation": True,
            "digital_signature": True,
            "nonce_protection": True,
            "persistent_storage": True,
            "atomic_authentication": True,
            "replay_protection": True,
            "security_audit": True,
            "automatic_audit_logging": True,
            "rate_limiting": True,
            "status": "MAINNET_READY"
        }
