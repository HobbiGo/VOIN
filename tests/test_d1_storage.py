"""
VOIN D1 STORAGE ENGINE TESTS
Version: 1.0.0

Tests for VOIND1StorageEngine.
Uses SQLite to simulate Cloudflare D1 behavior.
"""

import asyncio
import hashlib
import json
import math
import sqlite3
import time

from types import SimpleNamespace

import pytest

from security.d1_storage import VOIND1StorageEngine


# =========================================================
# D1 MOCK
# =========================================================

class FakeD1Result:

    def __init__(self, changes=0):
        self.meta = SimpleNamespace(changes=changes)


class FakeD1Statement:

    def __init__(self, database, sql):
        self.database = database
        self.sql = sql
        self.params = ()

    def bind(self, *params):
        self.params = params
        return self

    async def run(self):
        cursor = self.database.connection.execute(
            self.sql,
            self.params
        )

        return FakeD1Result(
            changes=max(cursor.rowcount, 0)
        )

    async def first(self):
        cursor = self.database.connection.execute(
            self.sql,
            self.params
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    async def all(self):
        cursor = self.database.connection.execute(
            self.sql,
            self.params
        )

        rows = cursor.fetchall()

        return SimpleNamespace(
            results=[dict(row) for row in rows]
        )


class FakeD1Database:

    def __init__(self):

        self.connection = sqlite3.connect(
            ":memory:",
            check_same_thread=False
        )

        self.connection.row_factory = sqlite3.Row

        self._create_schema()

    def prepare(self, sql):
        return FakeD1Statement(self, sql)

    async def batch(self, statements):

        results = []

        try:
            self.connection.execute("BEGIN")

            for statement in statements:

                cursor = self.connection.execute(
                    statement.sql,
                    statement.params
                )

                results.append(
                    FakeD1Result(
                        changes=max(cursor.rowcount, 0)
                    )
                )

            self.connection.commit()

            return results

        except Exception:
            self.connection.rollback()
            raise

    def _create_schema(self):

        self.connection.executescript(
            """
            CREATE TABLE nonces (
                wallet_address TEXT NOT NULL,
                nonce_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(wallet_address, nonce_hash),
                CHECK(used IN (0, 1))
            );

            CREATE TABLE challenges (
                challenge_id TEXT PRIMARY KEY,
                wallet_address TEXT NOT NULL,
                nonce_hash TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                CHECK(used IN (0, 1))
            );

            CREATE TABLE security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                wallet_address TEXT,
                reference_id TEXT,
                created_at REAL NOT NULL,
                details TEXT
            );

            CREATE TABLE network_peers (
                peer_id TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                status TEXT NOT NULL,
                registered_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                CHECK(status IN (
                    'PENDING',
                    'TRUSTED',
                    'REVOKED'
                ))
            );

            CREATE TABLE network_security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                peer_id TEXT,
                created_at REAL NOT NULL,
                details TEXT
            );

            CREATE TRIGGER trg_validate_challenge_nonce
            BEFORE UPDATE OF used ON challenges
            WHEN OLD.used = 0 AND NEW.used = 1
            BEGIN
                SELECT CASE
                    WHEN NOT EXISTS (
                        SELECT 1
                        FROM nonces
                        WHERE wallet_address = OLD.wallet_address
                          AND nonce_hash = OLD.nonce_hash
                          AND used = 0
                    )
                    THEN RAISE(
                        ABORT,
                        'Nonce unavailable'
                    )
                END;
            END;

            CREATE TRIGGER trg_consume_challenge_nonce
            AFTER UPDATE OF used ON challenges
            WHEN OLD.used = 0 AND NEW.used = 1
            BEGIN

                UPDATE nonces
                SET used = 1
                WHERE wallet_address = NEW.wallet_address
                  AND nonce_hash = NEW.nonce_hash
                  AND used = 0;

                INSERT INTO security_events (
                    event_type,
                    wallet_address,
                    reference_id,
                    created_at,
                    details
                )
                VALUES (
                    'AUTHENTICATION_CONSUMED',
                    NEW.wallet_address,
                    NEW.challenge_id,
                    NEW.created_at,
                    '{"status":"consumed"}'
                );

            END;
            """
        )

    def close(self):
        self.connection.close()


# =========================================================
# TEST FIXTURES
# =========================================================

WALLET = "0x1234567890abcdef1234567890abcdef12345678"

INVALID_WALLET = "0xINVALID"

NONCE = "voin-test-nonce-001"


def execute(coroutine):
    return asyncio.run(coroutine)


@pytest.fixture
def database():

    db = FakeD1Database()

    yield db

    db.close()


@pytest.fixture
def engine(database):

    return VOIND1StorageEngine(database)


# =========================================================
# ENGINE TESTS
# =========================================================

def test_engine_creation(database):

    engine = VOIND1StorageEngine(database)

    info = engine.engine_info()

    assert info["engine"] == "VOIND1StorageEngine"
    assert info["version"] == "1.0.2"
    assert info["database"] == "Cloudflare D1"
    assert info["async"] is True


def test_database_required():

    with pytest.raises(ValueError):
        VOIND1StorageEngine(None)


# =========================================================
# WALLET VALIDATION
# =========================================================

def test_wallet_normalization(engine):

    result = engine._normalize_wallet(
        "  0x1234567890ABCDEF1234567890ABCDEF12345678  "
    )

    assert result == WALLET


@pytest.mark.parametrize(
    "wallet",
    [
        None,
        "",
        "invalid",
        "0x123",
        INVALID_WALLET,
        "0x" + ("g" * 40),
    ]
)
def test_invalid_wallet_rejected(engine, wallet):

    with pytest.raises(ValueError):
        engine._normalize_wallet(wallet)


# =========================================================
# NONCE TESTS
# =========================================================

def test_save_nonce(engine, database):

    result = execute(
        engine.save_nonce(WALLET, NONCE)
    )

    assert result is True

    row = database.connection.execute(
        """
        SELECT *
        FROM nonces
        WHERE wallet_address = ?
        """,
        (WALLET,)
    ).fetchone()

    assert row is not None
    assert row["used"] == 0

    expected_hash = hashlib.sha256(
        NONCE.encode("utf-8")
    ).hexdigest()

    assert row["nonce_hash"] == expected_hash

    assert row["nonce_hash"] != NONCE


def test_nonce_created_audit(engine, database):

    execute(
        engine.save_nonce(WALLET, NONCE)
    )

    row = database.connection.execute(
        """
        SELECT event_type
        FROM security_events
        WHERE event_type = 'NONCE_CREATED'
        """
    ).fetchone()

    assert row is not None


def test_consume_nonce_once(engine):

    execute(
        engine.save_nonce(WALLET, NONCE)
    )

    first = execute(
        engine.consume_nonce(WALLET, NONCE)
    )

    second = execute(
        engine.consume_nonce(WALLET, NONCE)
    )

    assert first is True
    assert second is False


def test_consume_unknown_nonce(engine):

    result = execute(
        engine.consume_nonce(WALLET, "unknown-nonce")
    )

    assert result is False


def test_invalid_nonce_rejected(engine):

    with pytest.raises(ValueError):
        execute(
            engine.save_nonce(WALLET, "")
        )


# =========================================================
# CHALLENGE TESTS
# =========================================================

def test_create_challenge_atomic(engine, database):

    result = execute(
        engine.create_challenge_atomic(
            challenge_id="challenge-001",
            wallet_address=WALLET,
            nonce=NONCE,
            message="VOIN authentication test",
            expires_at=time.time() + 300
        )
    )

    assert result is True

    challenge = execute(
        engine.get_challenge("challenge-001")
    )

    assert challenge is not None
    assert challenge["wallet_address"] == WALLET
    assert challenge["used"] == 0

    nonce = database.connection.execute(
        "SELECT * FROM nonces"
    ).fetchone()

    assert nonce["used"] == 0


def test_challenge_creation_audit(engine, database):

    execute(
        engine.create_challenge_atomic(
            "challenge-audit",
            WALLET,
            NONCE,
            "Test message",
            time.time() + 300
        )
    )

    events = database.connection.execute(
        """
        SELECT event_type
        FROM security_events
        ORDER BY id
        """
    ).fetchall()

    event_types = [
        row["event_type"]
        for row in events
    ]

    assert "NONCE_CREATED" in event_types
    assert "CHALLENGE_CREATED" in event_types
    assert "CHALLENGE_CREATED_ATOMIC" in event_types


def test_challenge_expiration_rejected(engine):

    with pytest.raises(ValueError):

        execute(
            engine.create_challenge_atomic(
                "expired-challenge",
                WALLET,
                NONCE,
                "Expired",
                time.time() - 10
            )
        )


@pytest.mark.parametrize(
    "expiration",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
    ]
)
def test_invalid_expiration_rejected(
    engine,
    expiration
):

    with pytest.raises(ValueError):

        execute(
            engine.create_challenge_atomic(
                "invalid-expiration",
                WALLET,
                NONCE,
                "Test",
                expiration
            )
        )


def test_get_unknown_challenge(engine):

    result = execute(
        engine.get_challenge("unknown")
    )

    assert result is None


def test_consume_challenge_once(engine):

    execute(
        engine.create_challenge_atomic(
            "challenge-consume",
            WALLET,
            NONCE,
            "Test",
            time.time() + 300
        )
    )

    first = execute(
        engine.consume_challenge(
            "challenge-consume",
            WALLET
        )
    )

    second = execute(
        engine.consume_challenge(
            "challenge-consume",
            WALLET
        )
    )

    assert first is True
    assert second is False


# =========================================================
# AUTHENTICATION TESTS
# =========================================================

def test_consume_authentication(engine, database):

    execute(
        engine.create_challenge_atomic(
            "auth-001",
            WALLET,
            NONCE,
            "VOIN authentication",
            time.time() + 300
        )
    )

    result = execute(
        engine.consume_authentication(
            "auth-001",
            WALLET,
            NONCE
        )
    )

    assert result is True

    challenge = database.connection.execute(
        """
        SELECT used
        FROM challenges
        WHERE challenge_id = ?
        """,
        ("auth-001",)
    ).fetchone()

    nonce = database.connection.execute(
        """
        SELECT used
        FROM nonces
        WHERE wallet_address = ?
        """,
        (WALLET,)
    ).fetchone()

    assert challenge["used"] == 1
    assert nonce["used"] == 1


def test_authentication_nonce_cannot_be_reused(engine):

    execute(
        engine.create_challenge_atomic(
            "auth-002",
            WALLET,
            NONCE,
            "VOIN authentication",
            time.time() + 300
        )
    )

    first = execute(
        engine.consume_authentication(
            "auth-002",
            WALLET,
            NONCE
        )
    )

    second = execute(
        engine.consume_authentication(
            "auth-002",
            WALLET,
            NONCE
        )
    )

    assert first is True
    assert second is False


def test_wrong_authentication_nonce_rejected(engine):

    execute(
        engine.create_challenge_atomic(
            "auth-003",
            WALLET,
            NONCE,
            "VOIN authentication",
            time.time() + 300
        )
    )

    result = execute(
        engine.consume_authentication(
            "auth-003",
            WALLET,
            "wrong-nonce"
        )
    )

    assert result is False


def test_authentication_audit_created(engine, database):

    execute(
        engine.create_challenge_atomic(
            "auth-audit",
            WALLET,
            NONCE,
            "VOIN authentication",
            time.time() + 300
        )
    )

    execute(
        engine.consume_authentication(
            "auth-audit",
            WALLET,
            NONCE
        )
    )

    event = database.connection.execute(
        """
        SELECT *
        FROM security_events
        WHERE event_type = 'AUTHENTICATION_CONSUMED'
        """
    ).fetchone()

    assert event is not None
    assert event["reference_id"] == "auth-audit"


# =========================================================
# SECURITY AUDIT TESTS
# =========================================================

def test_log_event(engine, database):

    result = execute(
        engine.log_event(
            event_type="TEST_EVENT",
            wallet_address=WALLET,
            reference_id="reference-001",
            details={"status": "ok"}
        )
    )

    assert result is True

    event = database.connection.execute(
        """
        SELECT *
        FROM security_events
        WHERE event_type = 'TEST_EVENT'
        """
    ).fetchone()

    assert event is not None
    assert json.loads(event["details"]) == {
        "status": "ok"
    }


def test_log_event_without_wallet(engine):

    result = execute(
        engine.log_event(
            event_type="SYSTEM_EVENT",
            details={"source": "test"}
        )
    )

    assert result is True


def test_invalid_event_type_rejected(engine):

    with pytest.raises(ValueError):

        execute(
            engine.log_event(
                event_type=""
            )
        )


def test_get_security_events(engine):

    execute(
        engine.log_event("EVENT_ONE")
    )

    execute(
        engine.log_event("EVENT_TWO")
    )

    events = execute(
        engine.get_security_events(limit=10)
    )

    assert len(events) == 2


def test_get_wallet_security_events(engine):

    execute(
        engine.log_event(
            "WALLET_EVENT",
            wallet_address=WALLET
        )
    )

    events = execute(
        engine.get_wallet_security_events(WALLET)
    )

    assert len(events) == 1
    assert events[0]["wallet_address"] == WALLET


@pytest.mark.parametrize(
    "limit",
    [
        0,
        -1,
        1001,
        True,
        "10",
    ]
)
def test_invalid_security_event_limit(engine, limit):

    with pytest.raises(ValueError):

        execute(
            engine.get_security_events(limit=limit)
        )


# =========================================================
# NETWORK PEER TESTS
# =========================================================

def test_save_network_peer_starts_pending(engine, database):

    execute(
        engine.save_network_peer(
            "peer-001",
            "https://peer.example.com"
        )
    )

    peer = database.connection.execute(
        """
        SELECT *
        FROM network_peers
        WHERE peer_id = ?
        """,
        ("peer-001",)
    ).fetchone()

    assert peer is not None
    assert peer["status"] == "PENDING"


def test_get_network_peer(engine):

    execute(
        engine.save_network_peer(
            "peer-002",
            "https://peer.example.com"
        )
    )

    peer = execute(
        engine.get_network_peer("peer-002")
    )

    assert peer is not None
    assert peer["peer_id"] == "peer-002"


def test_list_network_peers(engine):

    execute(
        engine.save_network_peer(
            "peer-003",
            "https://peer3.example.com"
        )
    )

    peers = execute(
        engine.list_network_peers()
    )

    assert len(peers) == 1


def test_invalid_peer_status_rejected(engine):

    with pytest.raises(ValueError):

        execute(
            engine.list_network_peers(
                status="INVALID"
            )
        )


def test_revoke_network_peer(engine, database):

    execute(
        engine.save_network_peer(
            "peer-004",
            "https://peer4.example.com"
        )
    )

    # Simulate peer approval.
    database.connection.execute(
        """
        UPDATE network_peers
        SET status = 'TRUSTED'
        WHERE peer_id = ?
        """,
        ("peer-004",)
    )

    database.connection.commit()

    result = execute(
        engine.revoke_network_peer("peer-004")
    )

    assert result is True

    peer = execute(
        engine.get_network_peer("peer-004")
    )

    assert peer["status"] == "REVOKED"


# =========================================================
# NETWORK AUDIT TESTS
# =========================================================

def test_log_network_event(engine, database):

    result = execute(
        engine.log_network_event(
            event_type="PEER_TEST",
            peer_id="peer-001",
            details={"status": "ok"}
        )
    )

    assert result is True

    event = database.connection.execute(
        """
        SELECT *
        FROM network_security_events
        WHERE event_type = 'PEER_TEST'
        """
    ).fetchone()

    assert event is not None
    assert event["peer_id"] == "peer-001"


def test_get_network_security_events(engine):

    execute(
        engine.log_network_event(
            "NETWORK_EVENT"
        )
    )

    events = execute(
        engine.get_network_security_events()
    )

    assert len(events) == 1


@pytest.mark.parametrize(
    "limit",
    [
        0,
        -1,
        1001,
        True,
        "10",
    ]
)
def test_invalid_network_event_limit(engine, limit):

    with pytest.raises(ValueError):

        execute(
            engine.get_network_security_events(
                limit=limit
            )
        )
