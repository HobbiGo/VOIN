"""
VOIN SECURITY AUDIT ENGINE V1.0

Features:
- Security event recording
- Authentication success and failure tracking
- Replay attempt tracking
- Wallet-based audit history
- Security audit reports
- SQLite persistent storage

Security note:
Never store private keys, passwords, signatures,
or raw authentication nonces in audit details.
"""

import json

from security.storage import VOINStorageEngine


class VOINAuditEngine:

    VERSION = "1.0.0"

    EVENT_TYPES = {
        "AUTHENTICATION_SUCCESS",
        "AUTHENTICATION_FAILED",
        "REPLAY_ATTEMPT",
        "INVALID_CHALLENGE",
        "INVALID_NONCE",
        "EXPIRED_CHALLENGE",
        "UNAUTHORIZED_ACCESS",
        "SECURITY_WARNING"
    }

    def __init__(self, storage=None):

        self.storage = storage or VOINStorageEngine()

    @staticmethod
    def _validate_event_type(event_type):

        if event_type not in VOINAuditEngine.EVENT_TYPES:
            raise ValueError("Unsupported security event type")

        return event_type

    @staticmethod
    def _validate_details(details):

        if details is None:
            return {}

        if not isinstance(details, dict):
            raise ValueError("Audit details must be a dictionary")

        return details

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

    def get_events(self, limit=100):

        return self.storage.get_security_events(limit=limit)

    def get_wallet_events(
        self,
        wallet_address,
        limit=100
    ):

        wallet = self.storage._normalize_wallet(wallet_address)

        if not isinstance(limit, int) or limit <= 0:
            raise ValueError("Invalid event limit")

        with self.storage._connect() as connection:

            rows = connection.execute("""
                SELECT *
                FROM security_events
                WHERE wallet_address = ?
                ORDER BY id DESC
                LIMIT ?
            """, (
                wallet,
                limit
            )).fetchall()

        return [dict(row) for row in rows]

    def generate_report(self, limit=1000):

        events = self.get_events(limit=limit)

        report = {
            "engine": "VOIN Security Audit Engine",
            "version": self.VERSION,
            "total_events": len(events),
            "authentication_success": 0,
            "authentication_failed": 0,
            "replay_attempts": 0,
            "security_warnings": 0,
            "other_events": 0
        }

        for event in events:

            event_type = event["event_type"]

            if event_type == "AUTHENTICATION_SUCCESS":
                report["authentication_success"] += 1

            elif event_type == "AUTHENTICATION_FAILED":
                report["authentication_failed"] += 1

            elif event_type == "REPLAY_ATTEMPT":
                report["replay_attempts"] += 1

            elif event_type == "SECURITY_WARNING":
                report["security_warnings"] += 1

            else:
                report["other_events"] += 1

        report["status"] = "AUDIT_READY"

        return report

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Security Audit Engine",
            "version": cls.VERSION,
            "event_recording": True,
            "wallet_audit_history": True,
            "authentication_tracking": True,
            "replay_tracking": True,
            "security_reporting": True,
            "persistent_storage": "SQLite",
            "private_key_storage": False,
            "status": "READY_FOR_TESTING"
        }
