import sqlite3

from pathlib import Path

import pytest


# =====================================================
# MIGRATION FILES
# =====================================================

ROOT = Path(__file__).resolve().parents[1]


MIGRATION_001 = (
    ROOT / "migrations" /
    "0001_voin_security.sql"
)


MIGRATION_002 = (
    ROOT / "migrations" /
    "0002_voin_security_extensions.sql"
)


MIGRATION_003 = (
    ROOT / "migrations" /
    "0003_authentication_and_peer_lifecycle.sql"
)


# =====================================================
# TEST DATABASE
# =====================================================

@pytest.fixture
def database():

    connection = sqlite3.connect(":memory:")

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    migration_001 = MIGRATION_001.read_text(
        encoding="utf-8"
    )

    migration_002 = MIGRATION_002.read_text(
        encoding="utf-8"
    )

    migration_003 = MIGRATION_003.read_text(
        encoding="utf-8"
    )

    connection.executescript(
        migration_001
    )

    connection.executescript(
        migration_002
    )

    connection.executescript(
        migration_003
    )

    yield connection

    connection.close()


# =====================================================
# HELPERS
# =====================================================

def get_tables(connection):

    rows = connection.execute("""
        SELECT name

        FROM sqlite_master

        WHERE type = 'table'
    """).fetchall()

    return {
        row["name"]
        for row in rows
    }


def get_indexes(connection, table_name):

    rows = connection.execute("""
        SELECT name

        FROM sqlite_master

        WHERE type = 'index'

        AND tbl_name = ?
    """, (table_name,)).fetchall()

    return {
        row["name"]
        for row in rows
    }


def insert_nonce(
    connection,
    wallet,
    nonce_hash,
    used=0
):

    connection.execute("""
        INSERT INTO nonces (
            wallet_address,
            nonce_hash,
            created_at,
            used
        )

        VALUES (?, ?, ?, ?)
    """, (
        wallet,
        nonce_hash,
        1000,
        used
    ))


def insert_challenge(
    connection,
    challenge_id,
    wallet,
    nonce_hash,
    consumption_type="CHALLENGE",
    used=0
):

    connection.execute("""
        INSERT INTO challenges (
            challenge_id,
            wallet_address,
            nonce_hash,
            message,
            created_at,
            expires_at,
            used,
            consumption_type
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        challenge_id,
        wallet,
        nonce_hash,
        "VOIN authentication test",
        1000,
        2000,
        used,
        consumption_type
    ))


# =====================================================
# CONSTANTS
# =====================================================

TEST_WALLET = (
    "0x1234567890123456789012345678901234567890"
)


# =====================================================
# MIGRATION FILE TESTS
# =====================================================

def test_migration_files_exist():

    assert MIGRATION_001.exists()

    assert MIGRATION_002.exists()

    assert MIGRATION_003.exists()


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


# =====================================================
# WALLET RATE LIMIT TESTS
# =====================================================

def test_wallet_rate_limits_columns(database):

    rows = database.execute("""
        PRAGMA table_info(wallet_rate_limits)
    """).fetchall()

    columns = {
        row["name"]
        for row in rows
    }

    expected = {

        "wallet_address",

        "window_started_at",

        "attempts",

        "cooldown_until",

        "updated_at"

    }

    assert expected.issubset(columns)


def test_wallet_rate_limits_indexes(database):

    indexes = get_indexes(
        database,
        "wallet_rate_limits"
    )

    assert (
        "idx_wallet_rate_limits_updated"
        in indexes
    )


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
        TEST_WALLET,
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
        TEST_WALLET,
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
            TEST_WALLET,
            1000,
            -1,
            1000
        ))


# =====================================================
# SECURITY ALERT TESTS
# =====================================================

def test_security_alerts_columns(database):

    rows = database.execute("""
        PRAGMA table_info(security_alerts)
    """).fetchall()

    columns = {
        row["name"]
        for row in rows
    }

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
        TEST_WALLET,
        "HIGH",
        "Security event detected",
        1000
    ))

    row = database.execute("""
        SELECT *

        FROM security_alerts

        WHERE alert_id = ?
    """, (
        "alert-001",
    )).fetchone()

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
        "alert-001",
        "same-fingerprint",
        "REPLAY_ATTEMPT",
        "HIGH",
        "Security event",
        1000
    ))

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


# =====================================================
# CHALLENGE MIGRATION TESTS
# =====================================================

def test_challenges_has_consumption_type(database):

    rows = database.execute("""
        PRAGMA table_info(challenges)
    """).fetchall()

    columns = {
        row["name"]
        for row in rows
    }

    assert "consumption_type" in columns


def test_challenge_default_consumption_type(database):

    insert_challenge(
        database,
        "challenge-default",
        TEST_WALLET,
        "nonce-default"
    )

    row = database.execute("""
        SELECT consumption_type

        FROM challenges

        WHERE challenge_id = ?
    """, (
        "challenge-default",
    )).fetchone()

    assert row["consumption_type"] == "CHALLENGE"


def test_challenge_rejects_invalid_consumption_type(database):

    with pytest.raises(sqlite3.IntegrityError):

        insert_challenge(
            database,
            "challenge-invalid",
            TEST_WALLET,
            "nonce-invalid",
            consumption_type="INVALID"
        )


# =====================================================
# CHALLENGE CONSUMPTION TESTS
# =====================================================

def test_challenge_consumption_does_not_consume_nonce(database):

    insert_nonce(
        database,
        TEST_WALLET,
        "nonce-001"
    )

    insert_challenge(
        database,
        "challenge-001",
        TEST_WALLET,
        "nonce-001",
        consumption_type="CHALLENGE"
    )

    database.execute("""
        UPDATE challenges

        SET used = 1

        WHERE challenge_id = ?
    """, (
        "challenge-001",
    ))

    nonce = database.execute("""
        SELECT used

        FROM nonces

        WHERE wallet_address = ?

        AND nonce_hash = ?
    """, (
        TEST_WALLET,
        "nonce-001"
    )).fetchone()

    assert nonce["used"] == 0

    event = database.execute("""
        SELECT COUNT(*)

        FROM security_events

        WHERE event_type = 'AUTHENTICATION_CONSUMED'

        AND reference_id = ?
    """, (
        "challenge-001",
    )).fetchone()

    assert event[0] == 0


# =====================================================
# AUTHENTICATION TRIGGER TESTS
# =====================================================

def test_authentication_consumes_nonce(database):

    insert_nonce(
        database,
        TEST_WALLET,
        "nonce-002"
    )

    insert_challenge(
        database,
        "challenge-002",
        TEST_WALLET,
        "nonce-002",
        consumption_type="AUTHENTICATION"
    )

    database.execute("""
        UPDATE challenges

        SET used = 1

        WHERE challenge_id = ?
    """, (
        "challenge-002",
    ))

    nonce = database.execute("""
        SELECT used

        FROM nonces

        WHERE wallet_address = ?

        AND nonce_hash = ?
    """, (
        TEST_WALLET,
        "nonce-002"
    )).fetchone()

    assert nonce["used"] == 1


def test_authentication_creates_exactly_one_audit_event(database):

    insert_nonce(
        database,
        TEST_WALLET,
        "nonce-003"
    )

    insert_challenge(
        database,
        "challenge-003",
        TEST_WALLET,
        "nonce-003",
        consumption_type="AUTHENTICATION"
    )

    database.execute("""
        UPDATE challenges

        SET used = 1

        WHERE challenge_id = ?
    """, (
        "challenge-003",
    ))

    event = database.execute("""
        SELECT COUNT(*)

        FROM security_events

        WHERE event_type = 'AUTHENTICATION_CONSUMED'

        AND reference_id = ?
    """, (
        "challenge-003",
    )).fetchone()

    assert event[0] == 1


def test_authentication_rejects_used_nonce(database):

    insert_nonce(
        database,
        TEST_WALLET,
        "nonce-004",
        used=1
    )

    insert_challenge(
        database,
        "challenge-004",
        TEST_WALLET,
        "nonce-004",
        consumption_type="AUTHENTICATION"
    )

    with pytest.raises(sqlite3.IntegrityError):

        database.execute("""
            UPDATE challenges

            SET used = 1

            WHERE challenge_id = ?
        """, (
            "challenge-004",
        ))

    challenge = database.execute("""
        SELECT used

        FROM challenges

        WHERE challenge_id = ?
    """, (
        "challenge-004",
    )).fetchone()

    assert challenge["used"] == 0


def test_authentication_rejects_missing_nonce(database):

    insert_challenge(
        database,
        "challenge-005",
        TEST_WALLET,
        "nonce-missing",
        consumption_type="AUTHENTICATION"
    )

    with pytest.raises(sqlite3.IntegrityError):

        database.execute("""
            UPDATE challenges

            SET used = 1

            WHERE challenge_id = ?
        """, (
            "challenge-005",
        ))

    challenge = database.execute("""
        SELECT used

        FROM challenges

        WHERE challenge_id = ?
    """, (
        "challenge-005",
    )).fetchone()

    assert challenge["used"] == 0


# =====================================================
# NETWORK PEER MIGRATION TESTS
# =====================================================

def test_network_peer_accepts_pending(database):

    database.execute("""
        INSERT INTO network_peers (
            peer_id,
            endpoint,
            status,
            registered_at,
            updated_at
        )

        VALUES (?, ?, 'PENDING', ?, ?)
    """, (
        "peer-001",
        "https://example.test",
        1000,
        1000
    ))

    row = database.execute("""
        SELECT status

        FROM network_peers

        WHERE peer_id = ?
    """, (
        "peer-001",
    )).fetchone()

    assert row["status"] == "PENDING"


def test_network_peer_accepts_trusted(database):

    database.execute("""
        INSERT INTO network_peers (
            peer_id,
            endpoint,
            status,
            registered_at,
            updated_at
        )

        VALUES (?, ?, 'TRUSTED', ?, ?)
    """, (
        "peer-002",
        "https://trusted.example.test",
        1000,
        1000
    ))

    row = database.execute("""
        SELECT status

        FROM network_peers

        WHERE peer_id = ?
    """, (
        "peer-002",
    )).fetchone()

    assert row["status"] == "TRUSTED"


def test_network_peer_accepts_revoked(database):

    database.execute("""
        INSERT INTO network_peers (
            peer_id,
            endpoint,
            status,
            registered_at,
            updated_at
        )

        VALUES (?, ?, 'REVOKED', ?, ?)
    """, (
        "peer-003",
        "https://revoked.example.test",
        1000,
        1000
    ))

    row = database.execute("""
        SELECT status

        FROM network_peers

        WHERE peer_id = ?
    """, (
        "peer-003",
    )).fetchone()

    assert row["status"] == "REVOKED"


def test_network_peer_rejects_invalid_status(database):

    with pytest.raises(sqlite3.IntegrityError):

        database.execute("""
            INSERT INTO network_peers (
                peer_id,
                endpoint,
                status,
                registered_at,
                updated_at
            )

            VALUES (?, ?, ?, ?, ?)
        """, (
            "peer-invalid",
            "https://invalid.example.test",
            "UNKNOWN",
            1000,
            1000
        ))


def test_network_peer_status_index(database):

    indexes = get_indexes(
        database,
        "network_peers"
    )

    assert (
        "idx_network_peers_status"
        in indexes
    )


# =====================================================
# MIGRATION 002 REAPPLICATION TEST
# =====================================================

def test_migration_002_can_be_reapplied(database):

    migration_002 = MIGRATION_002.read_text(
        encoding="utf-8"
    )

    database.executescript(
        migration_002
    )

    tables = get_tables(database)

    assert "wallet_rate_limits" in tables

    assert "security_alerts" in tables
