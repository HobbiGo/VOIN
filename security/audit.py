"""
VOIN SECURITY AUDIT ENGINE V1.1.0
Centralized security event recording and reporting.
Features:
Authentication event tracking
Challenge and nonce event tracking
Replay attempt tracking
Rate limit event tracking
Security warning tracking
Wallet security history
Persistent event reporting
Storage API integration
Security note:
This module stores security metadata, not private keys.
"""

from security.storage import VOINStorageEngine


class VOINAuditEngine:

    VERSION = "1.1.0"

    EVENT_TYPES = {
        "AUTHENTICATION_SUCCESS",
        "AUTHENTICATION_FAILED",
        "AUTHENTICATION_CONSUMED",
        "REPLAY_ATTEMPT",
        "INVALID_CHALLENGE",
        "INVALID_NONCE",
        "EXPIRED_CHALLENGE",
        "UNAUTHORIZED_ACCESS",
        "SECURITY_WARNING",
        "RATE_LIMIT_EXCEEDED",
        "CHALLENGE_CREATED",
        "CHALLENGE_CONSUMED",
        "NONCE_CREATED",
        "NONCE_CONSUMED"
    }

    def __init__(self, storage=None):

        self.storage = (
            storage
            if storage is not None
            else VOINStorageEngine()
        )

    # --------------------------------------------------
    # VALIDATION
    # --------------------------------------------------

    @classmethod
    def _validate_event_type(cls, event_type):

        if not isinstance(event_type, str):
            raise ValueError("Invalid security event type")

        normalized = event_type.strip().upper()

        if normalized not in cls.EVENT_TYPES:
            raise ValueError("Unsupported security event type")

        return normalized

    @staticmethod
    def _validate_details(details):

        if details is None:
            return {}

        if not isinstance(details, dict):
            raise ValueError(
                "Audit details must be a dictionary"
            )

        return details

    # --------------------------------------------------
    # GENERAL EVENT RECORDING
    # --------------------------------------------------

    def record_event(
        self,
        event_type,
        wallet_address=None,
        reference_id=None,
        details=None
    ):

        event_type = self._validate_event_type(event_type)
        details = self._validate_details(details)

        self.storage.log_event(
            event_type=event_type,
            wallet_address=wallet_address,
            reference_id=reference_id,
            details=details
        )

        return True

    # --------------------------------------------------
    # AUTHENTICATION EVENTS
    # --------------------------------------------------

    def record_authentication_success(
        self,
        wallet_address,
        challenge_id
    ):

        return self.record_event(
            event_type="AUTHENTICATION_SUCCESS",
            wallet_address=wallet_address,
            reference_id=challenge_id,
            details={
                "result": "SUCCESS"
            }
        )

    def record_authentication_failure(
        self,
        wallet_address=None,
        challenge_id=None,
        reason="AUTHENTICATION_FAILED"
    ):

        return self.record_event(
            event_type="AUTHENTICATION_FAILED",
            wallet_address=wallet_address,
            reference_id=challenge_id,
            details={
                "result": "FAILED",
                "reason": str(reason)
            }
        )

    def record_authentication_consumed(
        self,
        wallet_address,
        challenge_id
    ):

        return self.record_event(
            event_type="AUTHENTICATION_CONSUMED",
            wallet_address=wallet_address,
            reference_id=challenge_id,
            details={
                "challenge_consumed": True,
                "nonce_consumed": True
            }
        )

    # --------------------------------------------------
    # CHALLENGE EVENTS
    # --------------------------------------------------

    def record_challenge_created(
        self,
        wallet_address,
        challenge_id
    ):

        return self.record_event(
            event_type="CHALLENGE_CREATED",
            wallet_address=wallet_address,
            reference_id=challenge_id,
            details={
                "result": "CREATED"
            }
        )

    def record_challenge_consumed(
        self,
        wallet_address,
        challenge_id
    ):

        return self.record_event(
            event_type="CHALLENGE_CONSUMED",
            wallet_address=wallet_address,
            reference_id=challenge_id,
            details={
                "result": "CONSUMED"
            }
        )

    def record_invalid_challenge(
        self,
        wallet_address=None,
        challenge_id=None,
        reason="INVALID_CHALLENGE"
    ):

        return self.record_event(
            event_type="INVALID_CHALLENGE",
            wallet_address=wallet_address,
            reference_id=challenge_id,
            details={
                "result": "REJECTED",
                "reason": str(reason)
            }
        )

    def record_expired_challenge(
        self,
        wallet_address=None,
        challenge_id=None
    ):

        return self.record_event(
            event_type="EXPIRED_CHALLENGE",
            wallet_address=wallet_address,
            reference_id=challenge_id,
            details={
                "result": "EXPIRED"
            }
        )

    # --------------------------------------------------
    # NONCE EVENTS
    # --------------------------------------------------

    def record_nonce_created(self, wallet_address):

        return self.record_event(
            event_type="NONCE_CREATED",
            wallet_address=wallet_address,
            details={
                "result": "CREATED"
            }
        )

    def record_nonce_consumed(self, wallet_address):

        return self.record_event(
            event_type="NONCE_CONSUMED",
            wallet_address=wallet_address,
            details={
                "result": "CONSUMED"
            }
        )

    def record_invalid_nonce(
        self,
        wallet_address=None,
        reference_id=None,
        reason="INVALID_NONCE"
    ):

        return self.record_event(
            event_type="INVALID_NONCE",
            wallet_address=wallet_address,
            reference_id=reference_id,
            details={
                "result": "REJECTED",
                "reason": str(reason)
            }
        )

    # --------------------------------------------------
    # REPLAY AND RATE LIMIT EVENTS
    # --------------------------------------------------

    def record_replay_attempt(
        self,
        wallet_address,
        reference_id=None
    ):

        return self.record_event(
            event_type="REPLAY_ATTEMPT",
            wallet_address=wallet_address,
            reference_id=reference_id,
            details={
                "result": "REJECTED",
                "protection": "REPLAY_PREVENTION"
            }
        )

    def record_rate_limit_exceeded(
        self,
        wallet_address,
        details=None
    ):

        event_details = {
            "result": "BLOCKED",
            "protection": "RATE_LIMIT"
        }

        if details is not None:

            if not isinstance(details, dict):
                raise ValueError(
                    "Rate limit details must be a dictionary"
                )

            event_details.update(details)

        return self.record_event(
            event_type="RATE_LIMIT_EXCEEDED",
            wallet_address=wallet_address,
            details=event_details
        )

    # --------------------------------------------------
    # ACCESS AND WARNING EVENTS
    # --------------------------------------------------

    def record_unauthorized_access(
        self,
        wallet_address=None,
        reference_id=None,
        reason="UNAUTHORIZED_ACCESS"
    ):

        return self.record_event(
            event_type="UNAUTHORIZED_ACCESS",
            wallet_address=wallet_address,
            reference_id=reference_id,
            details={
                "result": "REJECTED",
                "reason": str(reason)
            }
        )

    def record_security_warning(
        self,
        wallet_address=None,
        reference_id=None,
        reason="SECURITY_WARNING"
    ):

        return self.record_event(
            event_type="SECURITY_WARNING",
            wallet_address=wallet_address,
            reference_id=reference_id,
            details={
                "reason": str(reason)
            }
        )

    # --------------------------------------------------
    # EVENT RETRIEVAL
    # --------------------------------------------------

    def get_events(self, limit=100):

        return self.storage.get_security_events(
            limit=limit
        )

    def get_wallet_events(
        self,
        wallet_address,
        limit=100
    ):

        return self.storage.get_wallet_security_events(
            wallet_address=wallet_address,
            limit=limit
        )

    # --------------------------------------------------
    # AUDIT REPORT
    # --------------------------------------------------

    def generate_report(self, limit=1000):

        events = self.get_events(limit=limit)

        report = {
            "engine": "VOIN Security Audit Engine",
            "version": self.VERSION,
            "total_events": len(events),

            "authentication_success": 0,
            "authentication_failed": 0,
            "authentication_consumed": 0,

            "replay_attempts": 0,
            "invalid_challenges": 0,
            "invalid_nonces": 0,
            "expired_challenges": 0,
            "unauthorized_access": 0,

            "rate_limit_exceeded": 0,

            "challenges_created": 0,
            "challenges_consumed": 0,
            "nonces_created": 0,
            "nonces_consumed": 0,

            "security_warnings": 0,
            "other_events": 0
        }

        event_mapping = {
            "AUTHENTICATION_SUCCESS":
                "authentication_success",

            "AUTHENTICATION_FAILED":
                "authentication_failed",

            "AUTHENTICATION_CONSUMED":
                "authentication_consumed",

            "REPLAY_ATTEMPT":
                "replay_attempts",

            "INVALID_CHALLENGE":
                "invalid_challenges",

            "INVALID_NONCE":
                "invalid_nonces",

            "EXPIRED_CHALLENGE":
                "expired_challenges",

            "UNAUTHORIZED_ACCESS":
                "unauthorized_access",

            "RATE_LIMIT_EXCEEDED":
                "rate_limit_exceeded",

            "CHALLENGE_CREATED":
                "challenges_created",

            "CHALLENGE_CONSUMED":
                "challenges_consumed",

            "NONCE_CREATED":
                "nonces_created",

            "NONCE_CONSUMED":
                "nonces_consumed",

            "SECURITY_WARNING":
                "security_warnings"
        }

        for event in events:

            if not isinstance(event, dict):
                report["other_events"] += 1
                continue

            event_type = event.get("event_type")

            if not isinstance(event_type, str):
                report["other_events"] += 1
                continue

            event_type = event_type.strip().upper()

            report_key = event_mapping.get(event_type)

            if report_key is None:
                report["other_events"] += 1
            else:
                report[report_key] += 1

        report["status"] = "AUDIT_READY"

        return report

    # --------------------------------------------------
    # ENGINE INFORMATION
    # --------------------------------------------------

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Security Audit Engine",
            "version": cls.VERSION,

            "event_recording": True,
            "wallet_audit_history": True,

            "authentication_tracking": True,
            "challenge_tracking": True,
            "nonce_tracking": True,

            "replay_tracking": True,
            "rate_limit_tracking": True,

            "unauthorized_access_tracking": True,
            "security_reporting": True,

            "persistent_storage": "SQLite",
            "private_key_storage": False,

            "status": "READY_FOR_TESTING"
        }
