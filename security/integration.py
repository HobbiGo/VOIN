"""
VOIN SECURITY INTEGRATION ENGINE V1.5

Integrates:
- Wallet Verification Engine
- Persistent Challenge Engine
- Persistent Nonce Engine
- Digital Signature Engine
- SQLite Storage
- Atomic Authentication Consumption
- Replay Protection
- Security Audit Engine
- Rate Limiting Engine
"""

import re
import time

from security.verification import VOINVerificationEngine
from security.nonce import VOINNonceEngine
from security.audit import VOINAuditEngine
from security.rate_limit import VOINRateLimitEngine


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

    def _audit_failure(
        self,
        wallet_address=None,
        challenge_id=None,
        reason="AUTHENTICATION_FAILED"
    ):

        self.audit_engine.record_authentication_failure(
            wallet_address=wallet_address,
            challenge_id=challenge_id,
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

        challenge_result = self.challenge_engine.create_challenge(
            wallet_address
        )

        if not challenge_result["success"]:

            self._audit_failure(
                wallet_address=wallet_address,
                reason="CHALLENGE_GENERATION_FAILED"
            )

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

            self._audit_failure(
                reason="INVALID_ADDRESS"
            )

            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        # RATE LIMITING CHECK

        rate_result = self.rate_limit_engine.consume_attempt(
            wallet_address
        )

        if not rate_result["allowed"]:

            return {
                "success": False,
                "status": "RATE_LIMIT_EXCEEDED",
                "wallet_address": wallet_address,
                "attempts": rate_result["attempts"],
                "remaining": 0,
                "retry_after": rate_result["retry_after"]
            }

        storage = self.challenge_engine.storage

        if not self.challenge_engine.validate_challenge(
            challenge_id,
            wallet_address
        ):

            challenge = storage.get_challenge(challenge_id)

            if challenge:

                if challenge["used"] == 1:

                    self.audit_engine.record_replay_attempt(
                        wallet_address,
                        challenge_id
                    )

                    return {
                        "success": False,
                        "status": "CHALLENGE_ALREADY_USED"
                    }

                if challenge["expires_at"] <= int(time.time()):

                    self.audit_engine.record_event(
                        event_type="EXPIRED_CHALLENGE",
                        wallet_address=wallet_address,
                        reference_id=challenge_id,
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
                wallet_address=wallet_address,
                reference_id=challenge_id,
                details={
                    "result": "REJECTED"
                }
            )

            return {
                "success": False,
                "status": "INVALID_OR_EXPIRED_CHALLENGE"
            }

        challenge = storage.get_challenge(challenge_id)

        if not challenge:

            self._audit_failure(
                wallet_address=wallet_address,
                challenge_id=challenge_id,
                reason="CHALLENGE_NOT_FOUND"
            )

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

            self._audit_failure(
                wallet_address=wallet_address,
                challenge_id=challenge_id,
                reason="INVALID_CHALLENGE_NONCE"
            )

            return {
                "success": False,
                "status": "INVALID_CHALLENGE_NONCE"
            }

        nonce = match.group(1)

        nonce_hash = storage._hash_nonce(nonce)

        with storage._connect() as connection:

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

            self.audit_engine.record_event(
                event_type="INVALID_NONCE",
                wallet_address=wallet_address,
                reference_id=challenge_id,
                details={
                    "result": "REJECTED",
                    "reason": "NONCE_MISMATCH"
                }
            )

            return {
                "success": False,
                "status": "NONCE_MISMATCH"
            }

        if nonce_record["used"] == 1:

            self.audit_engine.record_replay_attempt(
                wallet_address,
                challenge_id
            )

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

            self._audit_failure(
                wallet_address=wallet_address,
                challenge_id=challenge_id,
                reason=result["status"]
            )

            return {
                "success": False,
                "status": result["status"]
            }

        # ATOMIC AUTHENTICATION CONSUMPTION

        consumed = storage.consume_authentication(
            challenge_id,
            wallet_address,
            nonce
        )

        if not consumed:

            self.audit_engine.record_replay_attempt(
                wallet_address,
                challenge_id
            )

            return {
                "success": False,
                "status": "AUTHENTICATION_CONSUMPTION_FAILED"
            }

        self.audit_engine.record_authentication_success(
            wallet_address=wallet_address,
            challenge_id=challenge_id
        )

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
            "atomic_authentication": True,
            "replay_protection": True,
            "security_audit": True,
            "automatic_audit_logging": True,
            "rate_limiting": True,
            "status": "READY_FOR_TESTING"
        }
