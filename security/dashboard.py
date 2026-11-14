"""
VOIN SECURITY DASHBOARD ENGINE V1.0

Features:
- Security event summary
- Authentication statistics
- Replay attempt monitoring
- Rate limit violation monitoring
- Security alert summary
- Engine status overview
- Recent security events
"""

from collections import Counter
from datetime import datetime, timezone


class VOINSecurityDashboard:

    VERSION = "1.0.0"

    def __init__(
        self,
        storage,
        audit_engine=None,
        monitor_engine=None,
        alert_engine=None,
        rate_limit_engine=None
    ):

        self.storage = storage
        self.audit_engine = audit_engine
        self.monitor_engine = monitor_engine
        self.alert_engine = alert_engine
        self.rate_limit_engine = rate_limit_engine

    def _get_events(self, limit=100):

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit must be a positive integer")

        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        events = self.storage.get_security_events(limit=limit)

        return [
            dict(event)
            for event in events
        ]

    def get_event_statistics(self, limit=1000):

        events = self._get_events(limit)

        event_counts = Counter(
            event["event_type"]
            for event in events
        )

        return {
            "total_events": len(events),

            "authentication_success": event_counts.get(
                "AUTHENTICATION_SUCCESS", 0
            ),

            "authentication_failed": event_counts.get(
                "AUTHENTICATION_FAILED", 0
            ),

            "replay_attempts": event_counts.get(
                "REPLAY_ATTEMPT", 0
            ),

            "rate_limit_violations": event_counts.get(
                "RATE_LIMIT_EXCEEDED", 0
            ),

            "invalid_challenges": event_counts.get(
                "INVALID_CHALLENGE", 0
            ),

            "invalid_nonces": event_counts.get(
                "INVALID_NONCE", 0
            ),

            "expired_challenges": event_counts.get(
                "EXPIRED_CHALLENGE", 0
            ),

            "event_breakdown": dict(event_counts)
        }

    def get_alert_statistics(self):

        if self.alert_engine is None:

            return {
                "available": False,
                "alerts": {}
            }

        return {
            "available": True,
            "alerts": self.alert_engine.get_alert_summary()
        }

    def get_engine_status(self):

        engines = {
            "storage": self.storage,
            "audit": self.audit_engine,
            "monitor": self.monitor_engine,
            "alert": self.alert_engine,
            "rate_limiting": self.rate_limit_engine
        }

        result = {}

        for name, engine in engines.items():

            if engine is None:

                result[name] = {
                    "available": False,
                    "status": "NOT_CONFIGURED"
                }

                continue

            if name == "storage":
                info = engine.engine_info()
            else:
                info = engine.engine_info()

            result[name] = {
                "available": True,
                "status": info.get(
                    "status",
                    "UNKNOWN"
                ),
                "version": info.get(
                    "version",
                    "UNKNOWN"
                )
            }

        return result

    def get_recent_events(self, limit=20):

        events = self._get_events(limit)

        return {
            "total": len(events),
            "events": events
        }

    def get_wallet_security_status(self, wallet_address):

        if self.rate_limit_engine is None:

            return {
                "available": False,
                "status": "RATE_LIMITING_NOT_CONFIGURED"
            }

        return {
            "available": True,
            "rate_limit": self.rate_limit_engine.get_status(
                wallet_address
            )
        }

    def get_dashboard(self, event_limit=1000):

        statistics = self.get_event_statistics(
            limit=event_limit
        )

        alerts = self.get_alert_statistics()

        engines = self.get_engine_status()

        recent_events = self.get_recent_events(
            limit=20
        )

        return {
            "dashboard": "VOIN Security Dashboard",
            "version": self.VERSION,
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "security_statistics": statistics,

            "alert_statistics": alerts,

            "engine_status": engines,

            "recent_events": recent_events,

            "status": "READY_FOR_TESTING"
        }

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Security Dashboard",
            "version": cls.VERSION,
            "security_statistics": True,
            "alert_monitoring": True,
            "engine_status": True,
            "recent_events": True,
            "wallet_security_status": True,
            "status": "READY_FOR_TESTING"
        }
