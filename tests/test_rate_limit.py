"""
VOIN RATE LIMITING ENGINE TEST SUITE V1.0
"""

import pytest

from security.storage import VOINStorageEngine
from security.rate_limit import VOINRateLimitEngine


@pytest.fixture
def storage(tmp_path):
    db_path = tmp_path / "voin_rate_limit_test.db"
    return VOINStorageEngine(str(db_path))


@pytest.fixture
def engine(storage):
    return VOINRateLimitEngine(
        storage=storage,
        max_attempts=3,
        window_seconds=60,
        cooldown_seconds=30
    )


@pytest.fixture
def wallet():
    return "0x1234567890abcdef1234567890abcdef12345678"


def test_engine_creation(engine):
    info = engine.engine_info()

    assert info["engine"] == "VOIN Rate Limiting Engine"
    assert info["version"] == "1.0.0"
    assert info["status"] == "READY_FOR_TESTING"


def test_first_attempt_allowed(engine, wallet):
    result = engine.consume_attempt(wallet)

    assert result["allowed"] is True
    assert result["attempts"] == 1
    assert result["remaining"] == 2
    assert result["status"] == "ALLOWED"


def test_attempt_limit_enforced(engine, wallet):
    engine.consume_attempt(wallet)
    engine.consume_attempt(wallet)
    engine.consume_attempt(wallet)

    result = engine.consume_attempt(wallet)

    assert result["allowed"] is False
    assert result["status"] == "BLOCKED"
    assert result["remaining"] == 0


def test_cooldown_blocks_requests(engine, wallet):
    for _ in range(3):
        engine.consume_attempt(wallet)

    blocked = engine.consume_attempt(wallet)

    assert blocked["allowed"] is False

    status = engine.get_status(wallet)

    assert status["blocked"] is True
    assert status["retry_after"] > 0


def test_wallets_have_separate_limits(engine):
    wallet_a = "0x1111111111111111111111111111111111111111"
    wallet_b = "0x2222222222222222222222222222222222222222"

    for _ in range(3):
        engine.consume_attempt(wallet_a)

    result = engine.consume_attempt(wallet_b)

    assert result["allowed"] is True
    assert result["attempts"] == 1


def test_rate_limit_persistence(storage, wallet):
    engine1 = VOINRateLimitEngine(
        storage,
        max_attempts=3,
        window_seconds=60,
        cooldown_seconds=30
    )

    engine1.consume_attempt(wallet)
    engine1.consume_attempt(wallet)

    engine2 = VOINRateLimitEngine(
        storage,
        max_attempts=3,
        window_seconds=60,
        cooldown_seconds=30
    )

    status = engine2.get_status(wallet)

    assert status["attempts"] == 2
    assert status["remaining"] == 1


def test_reset_wallet(engine, wallet):
    engine.consume_attempt(wallet)
    engine.consume_attempt(wallet)

    assert engine.reset_wallet(wallet) is True

    status = engine.get_status(wallet)

    assert status["attempts"] == 0
    assert status["remaining"] == 3
    assert status["blocked"] is False


def test_violation_logged(storage, engine, wallet):
    for _ in range(4):
        engine.consume_attempt(wallet)

    events = storage.get_security_events(limit=100)

    violations = [
        event for event in events
        if event["event_type"] == "RATE_LIMIT_EXCEEDED"
    ]

    assert len(violations) >= 1


def test_invalid_wallet_rejected(engine):
    with pytest.raises(ValueError):
        engine.consume_attempt("invalid-wallet")


@pytest.mark.parametrize(
    "value",
    [0, -1, True, 1.5, "5"]
)
def test_invalid_configuration_rejected(storage, value):
    with pytest.raises(ValueError):
        VOINRateLimitEngine(
            storage,
            max_attempts=value
        )


def test_expired_window_resets_attempts(engine, wallet, monkeypatch):
    import security.rate_limit as rate_limit_module

    current_time = [1000.0]

    monkeypatch.setattr(
        rate_limit_module.time,
        "time",
        lambda: current_time[0]
    )

    engine.consume_attempt(wallet)
    engine.consume_attempt(wallet)
    engine.consume_attempt(wallet)

    current_time[0] += 61

    result = engine.consume_attempt(wallet)

    assert result["allowed"] is True
    assert result["attempts"] == 1
