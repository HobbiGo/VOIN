"""
VOIN SECURITY MONITORING ENGINE V1.0

Monitors security audit events and detects suspicious
activity using configurable event thresholds.
"""

from collections import Counter

from security.audit import VOINAuditEngine


class VOINSecurityMonitor:

    VERSION = "1.0.0"

    EVENT_TYPES = {
        "AUTHENTICATION_SUCCESS",
        "AUTHENTICATION_FAILED",
        "REPLAY_ATTEMPT",
        "INVALID_CHALLENGE",
        "INVALID_NONCE",
        "EXPIRED_CHALLENGE",
        "UNAUTHORIZED_ACCESS",
        "SECURITY_WARNING",
    }

    def __init__(self, audit_engine=None):

        self.audit = audit_engine or VO​INAuditEngine()

    @staticmethod
    def _validate_positive_integer(value, name):

        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be a positive integer")

        if value <= 0:
            raise ValueError(f"{name} must be a positive integer")

    @staticmethod
    def _get_event_type(event):

        if isinstance(event, dict):
            return event.get("event_type", "UNKNOWN")

        try:
            return event["event_type"]
        except (KeyError, TypeError, IndexError):
            return "UNKNOWN"

    def get_activity_summary(self, limit=1000):

        self._validate_positive_integer(limit, "limit")

        events = self.audit.get_events(limit=limit)

        counts = Counter(
            self._get_event_type(event)
            for event in events
        )

        summary = {
            "total_events": len(events),
            "authentication_success": counts["AUTHENTICATION_SUCCESS"],
            "authentication_failed": counts["AUTHENTICATION_FAILED"],
            "replay_attempts": counts["REPLAY_ATTEMPT"],
            "expired_challenges": counts["EXPIRED_CHALLENGE"],
            "invalid_challenges": counts["INVALID_CHALLENGE"],
            "invalid_nonces": counts["INVALID_NONCE"],
            "unauthorized_access": counts["UNAUTHORIZED_ACCESS"],
            "security_warnings": counts["SECURITY_WARNING"],
            "other_events": sum(
                count
                for event_type, count in counts.items()
                if event_type not in self.EVENT_TYPES
            ),
        }

        return summary

    def get_wallet_activity(self, wallet_address, limit=100):

        if not isinstance(wallet_address, str) or not wallet_address.strip():
            raise ValueError("Invalid wallet address")

        self._validate_positive_integer(limit, "limit")

        return self.audit.get_wallet_events(
            wallet_address=wallet_address,
            limit=limit
        )

    def detect_suspicious_activity(
        self,
        window_events=100,
        failure_threshold=5,
        replay_threshold=3
    ):

        self._validate_positive_integer(window_events, "window_events")
        self._validate_positive_integer(
            failure_threshold,
            "failure_threshold"
        )
        self._validate_positive_integer(
            replay_threshold,
            "replay_threshold"
        )

        events = self.audit.get_events(limit=window_events)

        counts = Counter(
            self._get_event_type(event)
            for event in events
        )

        failures = counts["AUTHENTICATION_FAILED"]
        replays = counts["REPLAY_ATTEMPT"]

        alerts = []

        if failures >= failure_threshold:
            alerts.append({
                "type": "AUTHENTICATION_FAILURE_SPIKE",
                "severity": "HIGH",
                "count": failures,
                "message": "Authentication failures exceeded the threshold."
            })

        if replays >= replay_threshold:
            alerts.append({
                "type": "REPLAY_ACTIVITY_SPIKE",
                "severity": "HIGH",
                "count": replays,
                "message": "Replay attempts exceeded the threshold."
            })

        return {
            "suspicious": len(alerts) > 0,
            "checked_events": len(events),
            "authentication_failures": failures,
            "replay_attempts": replays,
            "alerts": alerts
        }

    def get_security_status(
        self,
        window_events=100,
        failure_threshold=5,
        replay_threshold=3
    ):

        monitoring = self.detect_suspicious_activity(
            window_events=window_events,
            failure_threshold=failure_threshold,
            replay_threshold=replay_threshold
        )

        return {
            "status": (
                "WARNING"
                if monitoring["suspicious"]
                else "NORMAL"
            ),
            "monitoring": monitoring,
            "version": self.VERSION
        }

    def engine_info(self):

        return {
            "engine": "VOIN SECURITY MONITORING ENGINE",
            "version": self.VERSION,
            "audit_integration": True,
            "authentication_monitoring": True,
            "replay_monitoring": True,
            "threshold_alerts": True,
            "storage": "SQLite"
        }
