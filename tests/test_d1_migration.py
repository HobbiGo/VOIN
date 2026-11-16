import sqlite3
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]

MIGRATION_001 = (
    ROOT / "migrations" / "0001_voin_security.sql"
)

MIGRATION_002 = (
    ROOT / "migrations" / "0002_voin_security_extensions.sql"
)


@pytest.fixture
def database():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")

    migration_001 = MIGRATION_001.read_text(
        encoding="utf-8"
    )

    migration_002 = MIGRATION_002.read_text(
        encoding="utf-8"
    )

    connection.executescript(migration_001)
    connection.executescript(migration_002)

    yield connection

    connection.close()


def get_tables(connection):
    rows = connection.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
    """).fetchall()

    return {row["name"] for row in rows}


def get_indexes(connection, table_name):
    rows = connection.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'index'
        AND tbl_name = ?
    """, (table_name,)).fetchall()

    return {row["name"] for row in rows}


def test_migration_files_exist():
    assert MIGRATION_001.exists()
    assert MIGRATION_002.exists()


def test_migrations_create_all_required_tables(database):
    tables = get_tables(database)

    expected_tables = {
        "nonces",
        "challenges",
        "security_events",
        "network_peers",
        "network_security_events",
        "wallet_rate_limits",
        "security_alerts"
    }

    assert expected_tables.issubset(tables)


def test_wallet_rate_limits_columns(database):
    rows = database.execute("""
        PRAGMA table_info(wallet_rate_limits)
    """).fetchall()

    columns = {row["name"] for row in rows}

    expected = {
        "wallet_address",
        "window_started_at",
        "attempts",
        "cooldown_until",
        "updated_at"
    }

    assert expected.issubset(columns)


def test_security_alerts_columns(database):
    rows = database.execute("""
        PRAGMA table_info(security_alerts)
    """).fetchall()

    columns = {row["name"] for row in rows}

    expected = {
        "alert_id",
        "fingerprint",
        "event_id",
        "event_type",
        "wallet_address",
        "risk_level",
        "description",
        "status",
        "created_at",
        "acknowledged_at",
        "resolved_at"
    }

    assert expected.issubset(columns)


def test_wallet_rate_limits_indexes(database):
    indexes = get_indexes(
        database,
        "wallet_rate_limits"
    )

    assert "idx_wallet_rate_limits_updated" in indexes


def test_security_alerts_indexes(database):
    indexes = get_indexes(
        database,
        "security_alerts"
    )

    expected = {
        "idx_security_alerts_status",
        "idx_security_alerts_risk",
        "idx_security_alerts_created",
        "idx_security_alerts_wallet"
    }

    assert expected.issubset(indexes)


def test_wallet_rate_limit_insert(database):
    database.execute("""
        INSERT INTO wallet_rate_limits (
            wallet_address,
            window_started_at,
            attempts,
            cooldown_until,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        "0x1234567890123456789012345678901234567890",
        1000,
        1,
        None,
        1000
    ))

    row = database.execute("""
        SELECT *
        FROM wallet_rate_limits
        WHERE wallet_address = ?
    """, (
        "0x1234567890123456789012345678901234567890",
    )).fetchone()

    assert row is not None
    assert row["attempts"] == 1


def test_wallet_rate_limit_rejects_negative_attempts(database):
    with pytest.raises(sqlite3.IntegrityError):
        database.execute("""
            INSERT INTO wallet_rate_limits (
                wallet_address,
                window_started_at,
                attempts,
                updated_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            "0x1234567890123456789012345678901234567890",
            1000,
            -1,
            1000
        ))


def test_security_alert_insert(database):
    database.execute("""
        INSERT INTO security_alerts (
            alert_id,
            fingerprint,
            event_id,
            event_type,
            wallet_address,
            risk_level,
            description,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "alert-001",
        "fingerprint-001",
        1,
        "REPLAY_ATTEMPT",
        "0x1234567890123456789012345678901234567890",
        "HIGH",
        "Security event detected",
        1000
    ))

    row = database.execute("""
        SELECT *
        FROM security_alerts
        WHERE alert_id = ?
    """, ("alert-001",)).fetchone()

    assert row is not None
    assert row["status"] == "OPEN"
    assert row["risk_level"] == "HIGH"


def test_security_alert_rejects_invalid_risk_level(database):
    with pytest.raises(sqlite3.IntegrityError):
        database.execute("""
            INSERT INTO security_alerts (
                alert_id,
                fingerprint,
                event_type,
                risk_level,
                description,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "alert-invalid",
            "fingerprint-invalid",
            "REPLAY_ATTEMPT",
            "UNKNOWN",
            "Invalid risk",
            1000
        ))


def test_security_alert_rejects_invalid_status(database):
    with pytest.raises(sqlite3.IntegrityError):
        database.execute("""
            INSERT INTO security_alerts (
                alert_id,
                fingerprint,
                event_type,
                risk_level,
                description,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "alert-invalid-status",
            "fingerprint-invalid-status",
            "REPLAY_ATTEMPT",
            "HIGH",
            "Invalid status",
            "UNKNOWN",
            1000
        ))


def test_security_alert_prevents_duplicate_fingerprint(database):
    values = (
        "alert-001",
        "same-fingerprint",
        "REPLAY_ATTEMPT",
        "HIGH",
        "Security event",
        1000
    )

    database.execute("""
        INSERT INTO security_alerts (
            alert_id,
            fingerprint,
            event_type,
            risk_level,
            description,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, values)

    with pytest.raises(sqlite3.IntegrityError):
        database.execute("""
            INSERT INTO security_alerts (
                alert_id,
                fingerprint,
                event_type,
                risk_level,
                description,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "alert-002",
            "same-fingerprint",
            "REPLAY_ATTEMPT",
            "HIGH",
            "Duplicate event",
            1001
        ))


def test_migration_002_can_be_reapplied(database):
    migration_002 = MIGRATION_002.read_text(
        encoding="utf-8"
    )

    database.executescript(migration_002)

    tables = get_tables(database)

    assert "wallet_rate_limits" in tables
    assert "security_alerts" in tables
