"""
VOIN SECURITY ALERT ENGINE V1.0

Security alert generation and incident management.

Features:
- Security event risk classification
- Persistent SQLite alerts
- Duplicate alert prevention
- Alert acknowledgment
- Alert resolution
- Alert reporting
"""

import sqlite3
import time
import hashlib

from pathlib import Path


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
        "SECURITY_WARNING": "HIGH"
    }

    def __init__(self, storage):

        if storage is None:
            raise ValueError("Storage engine is required")

        self.storage = storage
        self.database_path = storage.database_path

        self._initialize_database()

    def _connect(self):

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

        source = "|".join([
            str(event.get("id")),
            str(event.get("event_type")),
            str(event.get("wallet_address")),
            str(event.get("reference_id"))
        ])

        return hashlib.sha256(
            source.encode("utf-8")
        ).hexdigest()

    def _classify_risk(self, event_type):

        return self.EVENT_RISK_MAP.get(
            event_type,
            "MEDIUM"
        )

    def process_event(self, event):

        if not isinstance(event, dict):
            raise ValueError("Invalid security event")

        event_id = event.get("id")
        event_type = event.get("event_type")

        if not isinstance(event_id, int) or event_id <= 0:
            raise ValueError("Invalid event ID")

        if not isinstance(event_type, str) or not event_type:
            raise ValueError("Invalid event type")

        wallet = event.get("wallet_address")
        reference_id = event.get("reference_id")

        risk_level = self._classify_risk(event_type)

        fingerprint = self._fingerprint(event)

        alert_id = hashlib.sha256(
            f"VOIN-ALERT-{fingerprint}".encode("utf-8")
        ).hexdigest()

        description = (
            f"Security event detected: {event_type}"
        )

        timestamp = int(time.time())

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

        if not isinstance(limit, int) or limit <= 0:
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

        timestamp = int(time.time())

        with self._connect() as connection:

            cursor = connection.execute("""
                UPDATE security_alerts
                SET status = 'ACKNOWLEDGED',
                    acknowledged_at = ?
                WHERE alert_id = ?
                AND status = 'OPEN'
            """, (
                timestamp,
                alert_id
            ))

            return cursor.rowcount == 1

    def resolve_alert(self, alert_id):

        timestamp = int(time.time())

        with self._connect() as connection:

            cursor = connection.execute("""
                UPDATE security_alerts
                SET status = 'RESOLVED',
                    resolved_at = ?
                WHERE alert_id = ?
                AND status IN ('OPEN', 'ACKNOWLEDGED')
            """, (
                timestamp,
                alert_id
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
            "persistent_alerts": True,
            "duplicate_prevention": True,
            "risk_classification": True,
            "incident_management": True,
            "status": "READY_FOR_TESTING"
        }
