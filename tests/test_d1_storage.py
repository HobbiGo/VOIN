"""
VOIN D1 STORAGE TEST SUITE
Version: 1.0.0

Tests D1 storage behavior using a SQLite-backed D1 mock.
These tests do not replace real Cloudflare D1 integration tests.
"""

import asyncio
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from security.d1_storage import VOIND1StorageEngine


# =========================================================
# D1 MOCK
# =========================================================

class FakeStatement:

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
        self.database.connection.commit()

        return SimpleNamespace(
            meta=SimpleNamespace(changes=cursor.rowcount)
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

        return SimpleNamespace(
            results=[dict(row) for row in cursor.fetchall()]
        )


class FakeD1Database:

    def __init__(self):
        self.connection = sqlite3.connect(
            ":memory:",
            isolation_level=None
        )
        self.connection.row_factory = sqlite3.Row

        migration = (
            Path(__file__).resolve().parent.parent
            / "migrations"
            / "0001_voin_security.sql"
        )

        if not migration.exists():
            raise FileNotFoundError(
                f"D1 migration not found: {migration}"
            )

        self.connection.executescript(
            migration.read_text(encoding="utf-8")
        )

    def prepare(self, sql):
        return FakeStatement(self, sql)

    async def batch(self, statements):
        results = []

        self.connection.execute("BEGIN")

        try:
            for statement in statements:
                cursor = self.connection.execute(
                    statement.sql,
                    statement.params
                )

                results.append(
                    SimpleNamespace(
                        meta=SimpleNamespace(
                            changes=cursor.rowcount
                        )
                    )
                )

            self.connection.commit()

        except Exception:
            self.connection.rollback()
            raise

        return results

    def close(self):
        self.connection.close()


# =========================================================
# TEST FIXTURES
# =========================================================

@pytest.fixture
def storage():

    database = FakeD1Database()
    engine = VOIND1StorageEngine(database)

    yield engine

    database.close()


def execute(coroutine):
    return asyncio.run(coroutine)


WALLET = "0x1234567890abcdef1234567890abcdef12345678"
NONCE = "a" * 64
CHALLENGE_ID = "challenge-test-001"
MESSAGE = "VOIN authentication test"


# =========================================================
# 1. ENGINE INFORMATION
# =========================================================

def test_engine_info(storage):

    info = storage.engine_info()

    assert info["engine"] == "VOIND1StorageEngine"
    assert info["version"] == "1.0.1"
    assert info["database"] == "Cloudflare D1"
    assert info["async"] is True


# =========================================================
# 2. NONCE STORAGE
# =========================================================

def test_save_nonce(storage):

    result = execute(
        storage.save_nonce(WALLET, NONCE)
    )

    assert result is True

    events = execute(
        storage.get_security_events()
    )

    assert any(
        event["event_type"] == "NONCE_CREATED"
        for event in events
    )


def test_consume_nonce(storage):

    execute(
        storage.save_nonce(WALLET, NONCE)
    )

    first = execute(
        storage.consume_nonce(WALLET, NONCE)
    )

    second = execute(
        storage.consume_nonce(WALLET, NONCE)
    )

    assert first is True
    assert second is False


# =========================================================
# 3. CHALLENGE CREATION
# =========================================================

def test_create_challenge_atomic(storage):

    import time

    expires_at = time.time() + 300

    result = execute(
        storage.create_challenge_atomic(
            CHALLENGE_ID,
            WALLET,
            NONCE,
            MESSAGE,
            expires_at
        )
    )

    assert result is True

    challenge = execute(
        storage.get_challenge(CHALLENGE_ID)
    )

    assert challenge is not None
    assert challenge["wallet_address"] == WALLET
    assert challenge["used"] == 0


def test_challenge_creation_audit(storage):

    import time

    execute(
        storage.create_challenge_atomic(
            CHALLENGE_ID,
            WALLET,
            NONCE,
            MESSAGE,
            time.time() + 300
        )
    )

    events = execute(
        storage.get_security_events()
    )

    event_types = [
        event["event_type"]
        for event in events
    ]

    assert "NONCE_CREATED" in event_types
    assert "CHALLENGE_CREATED" in event_types
    assert "CHALLENGE_CREATED_ATOMIC" in event_types


# =========================================================
# 4. ATOMIC AUTHENTICATION
# =========================================================

def test_consume_authentication(storage):

    import time

    execute(
        storage.create_challenge_atomic(
            CHALLENGE_ID,
            WALLET,
            NONCE,
            MESSAGE,
            time.time() + 300
        )
    )

    result = execute(
        storage.consume_authentication(
            CHALLENGE_ID,
            WALLET,
            NONCE
        )
    )

    assert result is True

    challenge = execute(
        storage.get_challenge(CHALLENGE_ID)
    )

    assert challenge["used"] == 1

    nonce_hash = storage._hash_nonce(NONCE)

    nonce_row = execute(
        storage._first(
            """
            SELECT used
            FROM nonces
            WHERE wallet_address = ?
              AND nonce_hash = ?
            """,
            (WALLET, nonce_hash)
        )
    )

    assert nonce_row["used"] == 1


def test_prevent_authentication_replay(storage):

    import time

    execute(
        storage.create_challenge_atomic(
            CHALLENGE_ID,
            WALLET,
            NONCE,
            MESSAGE,
            time.time() + 300
        )
    )

    first = execute(
        storage.consume_authentication(
            CHALLENGE_ID,
            WALLET,
            NONCE
        )
    )

    second = execute(
        storage.consume_authentication(
            CHALLENGE_ID,
            WALLET,
            NONCE
        )
    )

    assert first is True
    assert second is False


def test_wrong_nonce_does_not_consume_challenge(storage):

    import time

    execute(
        storage.create_challenge_atomic(
            CHALLENGE_ID,
            WALLET,
            NONCE,
            MESSAGE,
            time.time() + 300
        )
    )

    result = execute(
        storage.consume_authentication(
            CHALLENGE_ID,
            WALLET,
            "b" * 64
        )
    )

    assert result is False

    challenge = execute(
        storage.get_challenge(CHALLENGE_ID)
    )

    assert challenge["used"] == 0


def test_expired_challenge_rejected(storage):

    import time

    execute(
        storage.create_challenge_atomic(
            CHALLENGE_ID,
            WALLET,
            NONCE,
            MESSAGE,
            time.time() - 10
        )
    )

    result = execute(
        storage.consume_authentication(
            CHALLENGE_ID,
            WALLET,
            NONCE
        )
    )

    assert result is False

    challenge = execute(
        storage.get_challenge(CHALLENGE_ID)
    )

    assert challenge["used"] == 0


# =========================================================
# 5. ATOMIC ROLLBACK
# =========================================================

def test_challenge_batch_rollback(storage):

    import time

    execute(
        storage.create_challenge_atomic(
            CHALLENGE_ID,
            WALLET,
            NONCE,
            MESSAGE,
            time.time() + 300
        )
    )

    with pytest.raises(sqlite3.IntegrityError):

        execute(
            storage.create_challenge_atomic(
                CHALLENGE_ID,
                WALLET,
                "c" * 64,
                MESSAGE,
                time.time() + 300
            )
        )

    events = execute(
        storage.get_security_events()
    )

    # Failed batch must not add another challenge audit.
    challenge_events = [
        event for event in events
        if event["event_type"] == "CHALLENGE_CREATED"
    ]

    assert len(challenge_events) == 1


# =========================================================
# 6. AUDIT STORAGE
# =========================================================

def test_log_security_event(storage):

    result = execute(
        storage.log_event(
            "SECURITY_WARNING",
            WALLET,
            "test-reference",
            {"source": "unit-test"}
        )
    )

    assert result is True

    events = execute(
        storage.get_wallet_security_events(WALLET)
    )

    assert any(
        event["event_type"] == "SECURITY_WARNING"
        for event in events
    )


def test_invalid_event_limit(storage):

    with pytest.raises(ValueError):
        execute(
            storage.get_security_events(limit=0)
        )

    with pytest.raises(ValueError):
        execute(
            storage.get_security_events(limit=1001)
        )


# =========================================================
# 7. INPUT VALIDATION
# =========================================================

def test_invalid_wallet_rejected(storage):

    with pytest.raises(ValueError):
        execute(
            storage.save_nonce(
                "invalid-wallet",
                NONCE
            )
        )


def test_invalid_nonce_rejected(storage):

    with pytest.raises(ValueError):
        execute(
            storage.save_nonce(
                WALLET,
                ""
            )
        )
