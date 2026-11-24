"""
VOIN SECURITY ALERT ENGINE V1.0

Security alert generation and incident management (BSC Mainnet / Chain ID 56).

Features:
- Security event risk classification
- Persistent SQLite alerts
- Duplicate alert prevention
- Alert acknowledgment
- Alert resolution
- Alert reporting
"""

import hashlib
import re
import sqlite3
import time

DEFAULT_CHAIN_ID = 56
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = "0x" + ("0" * 40)


class VOINAlertEngine:

    VERSION = "1.0.0"

    RISK_LEVELS = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    EVENT_RISK_MAP = {
        "AUTHENTICATION_SUCCESS": "LOW",
        "NONCE_CREATED": "LOW",
        "CHALLENGE_CREATED": "LOW",
        "AUTHENTICATION_FAILED": "MEDIUM",
        "INVALID_CHALLENGE": "MEDIUM",
        "INVALID_NONCE": "MEDIUM",
        "EXPIRED_CHALLENGE": "LOW",
        "REPLAY_ATTEMPT": "HIGH",
        "UNAUTHORIZED_ACCESS": "CRITICAL",
        "SECURITY_WARNING": "HIGH",
        "RATE_LIMIT_EXCEEDED": "HIGH",
    }

    def __init__(self, storage):

        if storage is None:
            raise ValueError("Storage engine is required")

        self.storage = storage
        self.database_path = str(storage.database_path)
        self._memory_uri = getattr(storage, "_memory_uri", None)

        self._initialize_database()

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

    @staticmethod
    def _normalize_wallet(wallet_address, *, allow_zero: bool = False):
        if wallet_address is None:
            return None
        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")
        cleaned = wallet_address.strip()
        if not cleaned:
            return None
        if not _EVM_ADDRESS_RE.match(cleaned):
            raise ValueError("Invalid EVM wallet address format")
        normalized = cleaned.lower()
        if not allow_zero and normalized == _ZERO_ADDRESS:
            raise ValueError("Zero address is not allowed")
        return normalized

    def _connect(self):

        if self._memory_uri is not None:
            connection = sqlite3.connect(
                self._memory_uri,
                uri=True,
                timeout=10,
                isolation_level=None
            )
        else:
            connection = sqlite3.connect(
                self.database_path,
                timeout=10,
                isolation_level=None
            )

        connection.row_factory = sqlite3.Row

        connection.execute("PRAGMA busy_timeout = 10000")

        return connection

    def _initialize_database(self):

        with self._connect() as connection:

            if self.database_path != ":memory:":
                connection.execute("PRAGMA journal_mode = WAL")

            connection.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    alert_id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL UNIQUE,
                    event_id INTEGER,
                    event_type TEXT NOT NULL,
                    wallet_address TEXT,
                    risk_level TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    created_at INTEGER NOT NULL,
                    acknowledged_at INTEGER,
                    resolved_at INTEGER
                )
            """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_security_alerts_status
                ON security_alerts(status)
            """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_security_alerts_risk
                ON security_alerts(risk_level)
            """)

    @staticmethod
    def _fingerprint(event):

        normalized_wallet = (
            event["wallet_address"].strip().lower()
            if isinstance(event.get("wallet_address"), str)
            and event.get("wallet_address").strip()
            else event.get("wallet_address")
        )

        normalized_type = (
            event["event_type"].strip().upper()
            if isinstance(event.get("event_type"), str)
            else event.get("event_type")
        )

        source = "|".join([
            str(event.get("id")),
            str(normalized_type),
            str(normalized_wallet),
            str(event.get("reference_id"))
        ])

        return hashlib.sha256(
            source.encode("utf-8")
        ).hexdigest()

    def _classify_risk(self, event_type):

        normalized_type = event_type.strip().upper()
        return self.EVENT_RISK_MAP.get(
            normalized_type,
            "MEDIUM"
        )

    def process_event(self, event):

        if not isinstance(event, dict):
            raise ValueError("Invalid security event")

        event_id = event.get("id")
        raw_event_type = event.get("event_type")

        if (
            isinstance(event_id, bool)
            or not isinstance(event_id, int)
            or event_id <= 0
        ):
            raise ValueError("Invalid event ID")

        if not isinstance(raw_event_type, str) or not raw_event_type.strip():
            raise ValueError("Invalid event type")

        event_type = raw_event_type.strip().upper()
        wallet = self._normalize_wallet(event.get("wallet_address"))
        reference_id = event.get("reference_id")

        risk_level = self._classify_risk(event_type)

        normalized_payload = {
            "id": event_id,
            "event_type": event_type,
            "wallet_address": wallet,
            "reference_id": reference_id,
        }

        fingerprint = self._fingerprint(normalized_payload)

        alert_id = hashlib.sha256(
            f"VOIN-ALERT-{fingerprint}".encode("utf-8")
        ).hexdigest()

        description = (
            f"Security event detected: {event_type}"
        )

        timestamp = self._now_ts()

        with self._connect() as connection:

            connection.execute("""
                INSERT OR IGNORE INTO security_alerts (
                    alert_id,
                    fingerprint,
                    event_id,
                    event_type,
                    wallet_address,
                    risk_level,
                    description,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)
            """, (
                alert_id,
                fingerprint,
                event_id,
                event_type,
                wallet,
                risk_level,
                description,
                timestamp
            ))

            row = connection.execute("""
                SELECT *
                FROM security_alerts
                WHERE fingerprint = ?
            """, (fingerprint,)).fetchone()

        return dict(row)

    def scan_events(self, limit=100):

        events = self.storage.get_security_events(
            limit=limit
        )

        alerts = []

        for event in reversed(events):

            alert = self.process_event(event)

            if alert:
                alerts.append(alert)

        return alerts

    def get_alerts(
        self,
        limit=100,
        status=None,
        risk_level=None
    ):

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit <= 0
        ):
            raise ValueError("Invalid alert limit")

        query = """
            SELECT *
            FROM security_alerts
            WHERE 1 = 1
        """

        parameters = []

        if status is not None:

            if status not in (
                "OPEN",
                "ACKNOWLEDGED",
                "RESOLVED"
            ):
                raise ValueError("Invalid alert status")

            query += " AND status = ?"
            parameters.append(status)

        if risk_level is not None:

            if risk_level not in self.RISK_LEVELS:
                raise ValueError("Invalid risk level")

            query += " AND risk_level = ?"
            parameters.append(risk_level)

        query += " ORDER BY created_at DESC LIMIT ?"

        parameters.append(limit)

        with self._connect() as connection:

            rows = connection.execute(
                query,
                parameters
            ).fetchall()

        return [dict(row) for row in rows]

    def acknowledge_alert(self, alert_id):

        if not isinstance(alert_id, str) or not alert_id.strip():
            return False

        timestamp = self._now_ts()

        with self._connect() as connection:

            cursor = connection.execute("""
                UPDATE security_alerts
                SET status = 'ACKNOWLEDGED',
                    acknowledged_at = ?
                WHERE alert_id = ?
                AND status = 'OPEN'
            """, (
                timestamp,
                alert_id.strip()
            ))

            return cursor.rowcount == 1

    def resolve_alert(self, alert_id):

        if not isinstance(alert_id, str) or not alert_id.strip():
            return False

        timestamp = self._now_ts()

        with self._connect() as connection:

            cursor = connection.execute("""
                UPDATE security_alerts
                SET status = 'RESOLVED',
                    resolved_at = ?
                WHERE alert_id = ?
                AND status IN ('OPEN', 'ACKNOWLEDGED')
            """, (
                timestamp,
                alert_id.strip()
            ))

            return cursor.rowcount == 1

    def get_alert_summary(self):

        with self._connect() as connection:

            rows = connection.execute("""
                SELECT
                    risk_level,
                    status,
                    COUNT(*) AS total
                FROM security_alerts
                GROUP BY risk_level, status
            """).fetchall()

        summary = {
            "total": 0,
            "by_risk": {
                level: 0
                for level in self.RISK_LEVELS
            },
            "by_status": {
                "OPEN": 0,
                "ACKNOWLEDGED": 0,
                "RESOLVED": 0
            }
        }

        for row in rows:

            total = row["total"]

            summary["total"] += total

            summary["by_risk"][row["risk_level"]] += total

            summary["by_status"][row["status"]] += total

        return summary

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Security Alert Engine",
            "version": cls.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "persistent_alerts": True,
            "duplicate_prevention": True,
            "risk_classification": True,
            "incident_management": True,
            "status": "MAINNET_READY"
        }
