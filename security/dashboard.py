"""
VOIN SECURITY DASHBOARD ENGINE V1.1

Integrates:
- SQLite Storage
- Security Audit
- Security Monitoring
- Security Alerts
- Rate Limiting
- Authentication Statistics
- Recent Security Events
- Wallet Security Status
"""

from collections import Counter
from datetime import datetime, timezone
import re

DEFAULT_CHAIN_ID = 56
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = "0x" + ("0" * 40)


class VOINSecurityDashboard:

    VERSION = "1.1.0"

    def __init__(
        self,
        storage,
        audit_engine=None,
        monitor_engine=None,
        alert_engine=None,
        rate_limit_engine=None
    ):

        if storage is None:
            raise ValueError("Storage engine is required")

        self.storage = storage
        self.audit_engine = audit_engine
        self.monitor_engine = monitor_engine
        self.alert_engine = alert_engine
        self.rate_limit_engine = rate_limit_engine

    @staticmethod
    def _normalize_wallet(wallet_address, *, allow_zero: bool = False) -> str:
        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        cleaned = wallet_address.strip()
        if not cleaned or not _EVM_ADDRESS_RE.match(cleaned):
            raise ValueError("Invalid EVM wallet address format")

        normalized = cleaned.lower()
        if not allow_zero and normalized == _ZERO_ADDRESS:
            raise ValueError("Zero address is not allowed")

        return normalized

    def _get_events(self, limit=100):

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit must be a positive integer")

        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        events = self.storage.get_security_events(limit=limit)

        return [dict(event) for event in events]

    def get_event_statistics(self, limit=1000):

        events = self._get_events(limit)

        event_counts = Counter(
            str(event.get("event_type", "")).strip().upper()
            for event in events
            if event.get("event_type") is not None
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

        get_summary = getattr(
            self.alert_engine,
            "get_alert_summary",
            None
        )
        if not callable(get_summary):
            return {
                "available": False,
                "alerts": {}
            }

        return {
            "available": True,
            "alerts": get_summary()
        }

    def get_monitoring_status(self):

        if self.monitor_engine is None:
            return {
                "available": False,
                "status": "NOT_CONFIGURED"
            }

        get_status = getattr(
            self.monitor_engine,
            "get_security_status",
            None
        )
        if not callable(get_status):
            return {
                "available": False,
                "status": "NOT_CONFIGURED"
            }

        result = get_status()

        return {
            "available": True,
            "status": result.get("status", "UNKNOWN"),
            "monitoring": result.get("monitoring", {}),
            "version": result.get("version")
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

            info_method = getattr(engine, "engine_info", None)
            if callable(info_method):
                info = info_method()
                result[name] = {
                    "available": True,
                    "status": info.get("status", "UNKNOWN"),
                    "version": info.get("version", "UNKNOWN")
                }
            else:
                result[name] = {
                    "available": True,
                    "status": "UNKNOWN",
                    "version": getattr(engine, "VERSION", "UNKNOWN")
                }

        return result

    def get_recent_events(self, limit=20):

        events = self._get_events(limit)

        return {
            "total": len(events),
            "events": events
        }

    def get_wallet_security_status(self, wallet_address):

        normalized_wallet = self._normalize_wallet(wallet_address)

        if self.rate_limit_engine is None:
            return {
                "available": False,
                "status": "RATE_LIMITING_NOT_CONFIGURED"
            }

        get_status = getattr(
            self.rate_limit_engine,
            "get_status",
            None
        )
        if not callable(get_status):
            return {
                "available": False,
                "status": "RATE_LIMITING_NOT_CONFIGURED"
            }

        return {
            "available": True,
            "rate_limit": get_status(normalized_wallet)
        }

    def get_dashboard(self, event_limit=1000):

        return {
            "dashboard": "VOIN Security Dashboard",
            "version": self.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "security_statistics":
                self.get_event_statistics(event_limit),

            "alert_statistics":
                self.get_alert_statistics(),

            "monitoring_status":
                self.get_monitoring_status(),

            "engine_status":
                self.get_engine_status(),

            "recent_events":
                self.get_recent_events(20),

            "status": "MAINNET_READY"
        }

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Security Dashboard",
            "version": cls.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "security_statistics": True,
            "alert_monitoring": True,
            "security_monitoring": True,
            "engine_status": True,
            "recent_events": True,
            "wallet_security_status": True,
            "status": "MAINNET_READY"
        }
