"""
VOIN D1 Rate Limit Tests
Version: 1.0.2

Tests for asynchronous D1 rate limit engine.
"""

import asyncio
import json
import sqlite3

import pytest

from security.d1_rate_limit import VOIND1RateLimitEngine


WALLET_A = "0x1111111111111111111111111111111111111111"
WALLET_B = "0x2222222222222222222222222222222222222222"


class FakeD1Result:
    def __init__(self, row=None, changes=0):
        self.row = row
        self.meta = {"changes": changes}

    def __getitem__(self, key):
        return self.row[key]


class FakeD1Statement:
    def __init__(self, database, sql):
        self.database = database
        self.sql = sql
        self.params = ()

    def bind(self, *params):
        self.params = params
        return self

    async def first(self):
        cursor = self.database.connection.execute(
            self.sql,
            self.params,
        )
        row = cursor.fetchone()
        self.database.connection.commit()

        if row is None:
            return None

        return dict(row)

    async def run(self):
        cursor = self.database.connection.execute(
            self.sql,
            self.params,
        )
        self.database.connection.commit()

        return FakeD1Result(changes=cursor.rowcount)

    async def all(self):
        cursor = self.database.connection.execute(
            self.sql,
            self.params,
        )
        rows = [dict(row) for row in cursor.fetchall()]
        self.database.connection.commit()

        return {"results": rows}


class FakeD1Database:
    def __init__(self):
        self.connection = sqlite3.connect(
            ":memory:",
            check_same_thread=False,
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript("""
        CREATE TABLE wallet_rate_limits (
            wallet_address TEXT PRIMARY KEY,
            window_started_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            cooldown_until INTEGER,
            updated_at INTEGER NOT NULL,
            CHECK (attempts >= 0)
        );

        CREATE TABLE security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            wallet_address TEXT,
            reference_id TEXT,
            created_at INTEGER NOT NULL,
            details TEXT
        );
        """)
        self.connection.commit()

    def prepare(self, sql):
        return FakeD1Statement(self, sql)

    def close(self):
        self.connection.close()


class FailingAuditDatabase(FakeD1Database):
    def prepare(self, sql):
        if "INSERT INTO security_events" in sql:
            raise RuntimeError("Simulated audit storage failure")
        return super().prepare(sql)


@pytest.fixture
def database():
    db = FakeD1Database()
    yield db
    db.close()


@pytest.fixture
def engine(database):
    return VOIND1RateLimitEngine(
        database=database,
        max_attempts=3,
        window_seconds=300,
        cooldown_seconds=60,
    )


def test_engine_creation(database):
    engine = VOIND1RateLimitEngine(database)
    info = engine.engine_info()

    assert info["engine"] == "VOIN D1 Rate Limit Engine"
    assert info["version"] == "1.0.1"
    assert info["storage"] == "Cloudflare D1"
    assert info["async"] is True


def test_engine_rejects_missing_database():
    with pytest.raises(ValueError):
        VOIND1RateLimitEngine(None)


@pytest.mark.parametrize(
    "config",
    [
        {"max_attempts": 0},
        {"max_attempts": -1},
        {"max_attempts": True},
        {"window_seconds": 0},
        {"window_seconds": -1},
        {"cooldown_seconds": 0},
        {"cooldown_seconds": False},
    ],
)
def test_invalid_configuration(database, config):
    with pytest.raises(ValueError):
        VOIND1RateLimitEngine(database, **config)


def test_invalid_wallet_rejected(engine):
    with pytest.raises(ValueError):
        engine._normalize_wallet("invalid-wallet")


@pytest.mark.asyncio
async def test_first_attempt_allowed(engine):
    result = await engine.consume_attempt(WALLET_A)

    assert result["success"] is True
    assert result["allowed"] is True
    assert result["attempts"] == 1
    assert result["remaining_attempts"] == 2


@pytest.mark.asyncio
async def test_maximum_attempts_activates_cooldown(engine):
    first = await engine.consume_attempt(WALLET_A)
    second = await engine.consume_attempt(WALLET_A)
    third = await engine.consume_attempt(WALLET_A)

    assert first["allowed"] is True
    assert second["allowed"] is True
    assert third["allowed"] is False
    assert third["attempts"] == 3
    assert third["cooldown_until"] is not None
    assert third["retry_after"] > 0


@pytest.mark.asyncio
async def test_attempt_during_cooldown_does_not_reset_cooldown(engine):
    for _ in range(3):
        await engine.consume_attempt(WALLET_A)

    status_before = await engine.get_status(WALLET_A)
    result = await engine.consume_attempt(WALLET_A)
    status_after = await engine.get_status(WALLET_A)

    assert result["allowed"] is False
    assert (
        status_after["cooldown_until"]
        == status_before["cooldown_until"]
    )
    assert status_after["blocked"] is True


@pytest.mark.asyncio
async def test_wallet_isolation(engine):
    for _ in range(3):
        await engine.consume_attempt(WALLET_A)

    status_a = await engine.get_status(WALLET_A)
    status_b = await engine.get_status(WALLET_B)

    assert status_a["blocked"] is True
    assert status_b["blocked"] is False
    assert status_b["attempts"] == 0


@pytest.mark.asyncio
async def test_get_status_for_new_wallet(engine):
    status = await engine.get_status(WALLET_A)

    assert status["success"] is True
    assert status["attempts"] == 0
    assert status["remaining_attempts"] == 3
    assert status["blocked"] is False


@pytest.mark.asyncio
async def test_reset_wallet(engine):
    for _ in range(3):
        await engine.consume_attempt(WALLET_A)

    result = await engine.reset_wallet(WALLET_A)

    assert result["success"] is True

    status = await engine.get_status(WALLET_A)

    assert status["attempts"] == 0
    assert status["blocked"] is False


@pytest.mark.asyncio
async def test_rate_limit_violation_logged(database, engine):
    for _ in range(3):
        await engine.consume_attempt(WALLET_A)

    events = database.connection.execute("""
        SELECT event_type, wallet_address, details
        FROM security_events
    """).fetchall()

    assert len(events) == 1
    assert events[0]["event_type"] == "RATE_LIMIT_EXCEEDED"
    assert events[0]["wallet_address"] == WALLET_A

    details = json.loads(events[0]["details"])
    assert details["attempts"] == 3
    assert details["max_attempts"] == 3


@pytest.mark.asyncio
async def test_repeated_blocked_attempts_are_logged(database, engine):
    for _ in range(5):
        await engine.consume_attempt(WALLET_A)

    cursor = database.connection.execute("""
        SELECT COUNT(*) AS total
        FROM security_events
        WHERE event_type = 'RATE_LIMIT_EXCEEDED'
    """)

    assert cursor.fetchone()["total"] == 3


@pytest.mark.asyncio
async def test_window_expiration_resets_attempts(engine, monkeypatch):
    fake_time = [1000]

    monkeypatch.setattr(
        "security.d1_rate_limit.time.time",
        lambda: fake_time[0],
    )

    await engine.consume_attempt(WALLET_A)
    await engine.consume_attempt(WALLET_A)

    fake_time[0] = 1301

    result = await engine.consume_attempt(WALLET_A)

    assert result["allowed"] is True
    assert result["attempts"] == 1


@pytest.mark.asyncio
async def test_cooldown_expiration_resets_attempts(engine, monkeypatch):
    fake_time = [1000]

    monkeypatch.setattr(
        "security.d1_rate_limit.time.time",
        lambda: fake_time[0],
    )

    for _ in range(3):
        await engine.consume_attempt(WALLET_A)

    blocked = await engine.get_status(WALLET_A)
    assert blocked["blocked"] is True

    fake_time[0] = blocked["cooldown_until"] + 1

    result = await engine.consume_attempt(WALLET_A)

    assert result["allowed"] is True
    assert result["attempts"] == 1
    assert result["cooldown_until"] is None


# V1.0.2 additional tests


@pytest.mark.asyncio
async def test_concurrent_attempts_preserve_attempt_count(engine):
    results = await asyncio.gather(
        *[
            engine.consume_attempt(WALLET_A)
            for _ in range(3)
        ]
    )

    status = await engine.get_status(WALLET_A)

    assert len(results) == 3
    assert status["attempts"] == 3
    assert status["blocked"] is True


@pytest.mark.asyncio
async def test_concurrent_wallets_remain_isolated(engine):
    await asyncio.gather(
        *[
            engine.consume_attempt(WALLET_A)
            for _ in range(3)
        ],
        *[
            engine.consume_attempt(WALLET_B)
            for _ in range(2)
        ],
    )

    status_a = await engine.get_status(WALLET_A)
    status_b = await engine.get_status(WALLET_B)

    assert status_a["attempts"] == 3
    assert status_a["blocked"] is True
    assert status_b["attempts"] == 2
    assert status_b["blocked"] is False


@pytest.mark.asyncio
async def test_insert_returning_persists_rate_limit_state(
    database,
    engine,
):
    result = await engine.consume_attempt(WALLET_A)

    assert result["attempts"] == 1

    row = database.connection.execute("""
        SELECT attempts
        FROM wallet_rate_limits
        WHERE wallet_address = ?
    """, (WALLET_A,)).fetchone()

    assert row is not None
    assert row["attempts"] == 1


@pytest.mark.asyncio
async def test_audit_failure_does_not_undo_rate_limit_state():
    database = FailingAuditDatabase()

    try:
        engine = VOIND1RateLimitEngine(
            database,
            max_attempts=1,
            window_seconds=300,
            cooldown_seconds=60,
        )

        with pytest.raises(RuntimeError):
            await engine.consume_attempt(WALLET_A)

        row = database.connection.execute("""
            SELECT attempts, cooldown_until
            FROM wallet_rate_limits
            WHERE wallet_address = ?
        """, (WALLET_A,)).fetchone()

        assert row is not None
        assert row["attempts"] == 1
        assert row["cooldown_until"] is not None
    finally:
        database.close()


@pytest.mark.asyncio
async def test_cooldown_remaining_attempts_stay_zero(engine):
    for _ in range(3):
        await engine.consume_attempt(WALLET_A)

    result = await engine.consume_attempt(WALLET_A)

    assert result["allowed"] is False
    assert result["remaining_attempts"] == 0
    assert result["retry_after"] > 0


@pytest.mark.asyncio
async def test_wallet_normalization_is_consistent(engine):
    result = await engine.consume_attempt(
        "  " + WALLET_A.upper() + "  "
    )

    assert result["wallet_address"] == WALLET_A

    status = await engine.get_status(WALLET_A)
    assert status["attempts"] == 1
