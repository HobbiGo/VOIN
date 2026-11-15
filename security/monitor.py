"""
VOIN SECURITY MONITORING ENGINE V1.1

Monitors security audit events and detects suspicious
activity using configurable event thresholds.

Compatible with:
- VOIN Audit Engine V1.0.0
- VOIN Storage Engine V1.3.0
- VOIN Security Integration V1.5.0
"""

from collections import Counter

from security.audit import VOINAuditEngine


class VOINSecurityMonitor:

    VERSION = "1.1.0"

    EVENT_TYPES = {
        "AUTHENTICATION_SUCCESS",
        "AUTHENTICATION_FAILED",
        "REPLAY_ATTEMPT",
        "INVALID_CHALLENGE",
        "INVALID_NONCE",
        "EXPIRED_CHALLENGE",
        "UNAUTHORIZED_ACCESS",
        "SECURITY_WARNING",
        "RATE_LIMIT_EXCEEDED",
    }

    def __init__(self, audit_engine=None):

        self.audit = audit_engine or VOINAuditEngine()

    @staticmethod
    def _validate_positive_integer(value, name):

        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"{name} must be a positive integer"
            )

        if value <= 0:
            raise ValueError(
                f"{name} must be a positive integer"
            )

    @staticmethod
    def _get_event_type(event):

        if not isinstance(event, dict):
            try:
                event_type = event["event_type"]
            except (KeyError, TypeError, IndexError):
                return "UNKNOWN"
        else:
            event_type = event.get("event_type")

        if not isinstance(event_type, str):
            return "UNKNOWN"

        event_type = event_type.strip().upper()

        return event_type if event_type else "UNKNOWN"

    def get_activity_summary(self, limit=1000):

        self._validate_positive_integer(limit, "limit")

        events = self.audit.get_events(limit=limit)

        counts = Counter(
            self._get_event_type(event)
            for event in events
        )

        summary = {
            "total_events": len(events),

            "authentication_success":
                counts["AUTHENTICATION_SUCCESS"],

            "authentication_failed":
                counts["AUTHENTICATION_FAILED"],

            "replay_attempts":
                counts["REPLAY_ATTEMPT"],

            "expired_challenges":
                counts["EXPIRED_CHALLENGE"],

            "invalid_challenges":
                counts["INVALID_CHALLENGE"],

            "invalid_nonces":
                counts["INVALID_NONCE"],

            "unauthorized_access":
                counts["UNAUTHORIZED_ACCESS"],

            "security_warnings":
                counts["SECURITY_WARNING"],

            "rate_limit_exceeded":
                counts["RATE_LIMIT_EXCEEDED"],

            "other_events": sum(
                count
                for event_type, count in counts.items()
                if event_type not in self.EVENT_TYPES
            ),
        }

        return summary

    def get_wallet_activity(
        self,
        wallet_address,
        limit=100
    ):

        if (
            not isinstance(wallet_address, str)
            or not wallet_address.strip()
        ):
            raise ValueError("Invalid wallet address")

        self._validate_positive_integer(limit, "limit")

        return self.audit.get_wallet_events(
            wallet_address=wallet_address,
            limit=limit
        )

    @staticmethod
    def _create_alert(
        alert_type,
        count,
        threshold,
        message
    ):

        return {
            "type": alert_type,
            "severity": "HIGH",
            "count": count,
            "threshold": threshold,
            "message": message
        }

    def detect_suspicious_activity(
        self,
        window_events=100,
        failure_threshold=5,
        replay_threshold=3,
        rate_limit_threshold=5,
        invalid_challenge_threshold=5,
        invalid_nonce_threshold=5,
        unauthorized_access_threshold=3
    ):

        thresholds = {
            "window_events": window_events,
            "failure_threshold": failure_threshold,
            "replay_threshold": replay_threshold,
            "rate_limit_threshold": rate_limit_threshold,
            "invalid_challenge_threshold":
                invalid_challenge_threshold,
            "invalid_nonce_threshold":
                invalid_nonce_threshold,
            "unauthorized_access_threshold":
                unauthorized_access_threshold,
        }

        for name, value in thresholds.items():

            self._validate_positive_integer(
                value,
                name
            )

        events = self.audit.get_events(
            limit=window_events
        )

        counts = Counter(
            self._get_event_type(event)
            for event in events
        )

        failures = counts["AUTHENTICATION_FAILED"]
        replays = counts["REPLAY_ATTEMPT"]

        rate_limits = counts["RATE_LIMIT_EXCEEDED"]

        invalid_challenges = counts["INVALID_CHALLENGE"]
        invalid_nonces = counts["INVALID_NONCE"]

        unauthorized = counts["UNAUTHORIZED_ACCESS"]

        alerts = []

        if failures >= failure_threshold:

            alerts.append(
                self._create_alert(
                    alert_type="AUTHENTICATION_FAILURE_SPIKE",
                    count=failures,
                    threshold=failure_threshold,
                    message=(
                        "Authentication failures exceeded "
                        "the configured threshold."
                    )
                )
            )

        if replays >= replay_threshold:

            alerts.append(
                self._create_alert(
                    alert_type="REPLAY_ACTIVITY_SPIKE",
                    count=replays,
                    threshold=replay_threshold,
                    message=(
                        "Replay attempts exceeded "
                        "the configured threshold."
                    )
                )
            )

        if rate_limits >= rate_limit_threshold:

            alerts.append(
                self._create_alert(
                    alert_type="RATE_LIMIT_SPIKE",
                    count=rate_limits,
                    threshold=rate_limit_threshold,
                    message=(
                        "Rate limit violations exceeded "
                        "the configured threshold."
                    )
                )
            )

        if invalid_challenges >= invalid_challenge_threshold:

            alerts.append(
                self._create_alert(
                    alert_type="INVALID_CHALLENGE_SPIKE",
                    count=invalid_challenges,
                    threshold=invalid_challenge_threshold,
                    message=(
                        "Invalid challenge events exceeded "
                        "the configured threshold."
                    )
                )
            )

        if invalid_nonces >= invalid_nonce_threshold:

            alerts.append(
                self._create_alert(
                    alert_type="INVALID_NONCE_SPIKE",
                    count=invalid_nonces,
                    threshold=invalid_nonce_threshold,
                    message=(
                        "Invalid nonce events exceeded "
                        "the configured threshold."
                    )
                )
            )

        if unauthorized >= unauthorized_access_threshold:

            alerts.append(
                self._create_alert(
                    alert_type="UNAUTHORIZED_ACCESS_SPIKE",
                    count=unauthorized,
                    threshold=unauthorized_access_threshold,
                    message=(
                        "Unauthorized access events exceeded "
                        "the configured threshold."
                    )
                )
            )

        return {
            "suspicious": len(alerts) > 0,
            "checked_events": len(events),

            "authentication_failures": failures,
            "replay_attempts": replays,

            "rate_limit_exceeded": rate_limits,

            "invalid_challenges": invalid_challenges,
            "invalid_nonces": invalid_nonces,

            "unauthorized_access": unauthorized,

            "alerts": alerts
        }

    def get_security_status(
        self,
        window_events=100,
        failure_threshold=5,
        replay_threshold=3,
        rate_limit_threshold=5,
        invalid_challenge_threshold=5,
        invalid_nonce_threshold=5,
        unauthorized_access_threshold=3
    ):

        monitoring = self.detect_suspicious_activity(
            window_events=window_events,
            failure_threshold=failure_threshold,
            replay_threshold=replay_threshold,
            rate_limit_threshold=rate_limit_threshold,
            invalid_challenge_threshold=invalid_challenge_threshold,
            invalid_nonce_threshold=invalid_nonce_threshold,
            unauthorized_access_threshold=unauthorized_access_threshold
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

            "rate_limit_monitoring": True,
            "challenge_monitoring": True,
            "nonce_monitoring": True,
            "unauthorized_access_monitoring": True,

            "threshold_alerts": True,
            "storage": "SQLite"
        }
