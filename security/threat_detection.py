"""
VOIN THREAT DETECTION ENGINE V1.0

Features:
- Failed authentication detection
- Repeated nonce detection
- Invalid digital signature detection
- Rate limit violation detection
- Event history
- Configurable detection thresholds
- Alert generation
- Thread-safe event processing
"""

import re
import secrets
import threading
import time
from collections import deque

_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
DEFAULT_CHAIN_ID = 56


class VOINThreatDetectionEngine:

    VERSION = "1.0.0"

    EVENT_TYPES = {
        "auth_failure",
        "nonce_reuse",
        "invalid_signature",
        "rate_limit_exceeded",
    }

    DEFAULT_WINDOW_SECONDS = 300
    DEFAULT_THRESHOLD = 5
    DEFAULT_MAX_EVENTS = 10000

    def __init__(
        self,
        window_seconds=DEFAULT_WINDOW_SECONDS,
        threshold=DEFAULT_THRESHOLD,
        max_events=DEFAULT_MAX_EVENTS,
    ):

        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or window_seconds <= 0
        ):
            raise ValueError("Invalid detection window")

        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, int)
            or threshold < 1
        ):
            raise ValueError("Invalid detection threshold")

        if (
            isinstance(max_events, bool)
            or not isinstance(max_events, int)
            or max_events < 1
        ):
            raise ValueError("Invalid maximum event count")

        self.window_seconds = int(window_seconds) if isinstance(window_seconds, int) else window_seconds
        self.threshold = threshold
        self.max_events = max_events

        self.events = deque(maxlen=max_events)
        self.alerts = deque(maxlen=max_events)

        self.last_alert_time = {}

        self.lock = threading.RLock()

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

    @staticmethod
    def _normalize_source(source: str) -> str:
        cleaned = source.strip()
        if _EVM_ADDRESS_RE.match(cleaned):
            return cleaned.lower()
        return cleaned

    def record_event(
        self,
        event_type,
        source="unknown",
        details=None,
    ):

        if event_type not in self.EVENT_TYPES:
            raise ValueError("Unsupported threat event type")

        if not isinstance(source, str) or not source.strip():
            raise ValueError("Invalid event source")

        if details is not None and not isinstance(details, dict):
            raise ValueError("Event details must be a dictionary")

        normalized_source = self._normalize_source(source)
        current_time = self._now_ts()

        event = {
            "event_type": event_type,
            "source": normalized_source,
            "details": dict(details or {}),
            "timestamp": current_time,
        }

        with self.lock:

            self.events.append(event)

            alert = self._analyze_event(event)

            return {
                "success": True,
                "event": dict(event),
                "alert_generated": alert is not None,
                "alert": dict(alert) if alert else None,
            }

    def _analyze_event(self, event):

        current_time = int(event["timestamp"])

        cutoff = current_time - self.window_seconds

        matching_events = [
            item
            for item in self.events
            if (
                item["event_type"] == event["event_type"]
                and item["source"] == event["source"]
                and item["timestamp"] >= cutoff
            )
        ]

        event_key = (
            event["event_type"],
            event["source"],
        )

        if len(matching_events) < self.threshold:
            return None

        if self.last_alert_time.get(event_key, 0) >= cutoff:
            return None

        alert = {
            "alert_id": (
                f"{current_time}-{secrets.token_hex(4)}-{event['event_type']}"
            ),
            "event_type": event["event_type"],
            "source": event["source"],
            "event_count": len(matching_events),
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "severity": "HIGH",
            "timestamp": current_time,
            "status": "DETECTED",
        }

        self.alerts.append(alert)

        self.last_alert_time[event_key] = current_time

        return alert

    def get_alerts(self, limit=100):

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit < 1
        ):
            raise ValueError("Invalid alert limit")

        with self.lock:

            selected = list(self.alerts)[-limit:]

            return {
                "success": True,
                "count": len(selected),
                "alerts": [
                    dict(alert)
                    for alert in reversed(selected)
                ],
            }

    def get_events(self, limit=100):

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit < 1
        ):
            raise ValueError("Invalid event limit")

        with self.lock:

            selected = list(self.events)[-limit:]

            return {
                "success": True,
                "count": len(selected),
                "events": [
                    dict(event)
                    for event in reversed(selected)
                ],
            }

    def get_status(self):

        with self.lock:

            return {
                "engine": "VOIN Threat Detection",
                "version": self.VERSION,
                "chain_id": DEFAULT_CHAIN_ID,
                "total_events": len(self.events),
                "total_alerts": len(self.alerts),
                "supported_event_types": sorted(self.EVENT_TYPES),
                "window_seconds": self.window_seconds,
                "threshold": self.threshold,
                "status": "ACTIVE",
            }

    def reset(self):

        with self.lock:

            self.events.clear()
            self.alerts.clear()
            self.last_alert_time.clear()

            return {
                "success": True,
                "message": "Threat detection history cleared",
            }

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Threat Detection Engine",
            "version": cls.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "authentication_failure_detection": True,
            "nonce_reuse_detection": True,
            "invalid_signature_detection": True,
            "rate_limit_detection": True,
            "event_history": True,
            "alert_generation": True,
            "thread_safe": True,
            "status": "MAINNET_READY",
        }
