"""
VOIN SECURITY PERSISTENCE TEST SUITE V1.0

Tests:
- SQLite persistence
- Challenge storage
- Nonce storage
- Atomic consumption
- Replay prevention
- Security audit logging
"""

import pytest
import time

from concurrent.futures import ThreadPoolExecutor

from security.storage import VOINStorageEngine


@pytest.fixture
def storage(tmp_path):
    database = tmp_path / "voin_test.db"
    return VOINStorageEngine(str(database))


@pytest.fixture
def wallet():
    return "0x1234567890123456789012345678901234567890"


@pytest.fixture
def nonce():
    return "a" * 64


def test_storage_engine_creation(storage):
    assert storage is not None


def test_engine_information(storage):

    info = storage.engine_info()

    assert info["engine"] == "VOIN Security Persistence Engine"
    assert info["database"] == "SQLite"
    assert info["persistent_challenges"] is True
    assert info["persistent_nonces"] is True
    assert info["atomic_consumption"] is True


def test_nonce_storage(storage, wallet, nonce):

    result = storage.save_nonce(wallet, nonce)

    assert result is True


def test_nonce_consumption(storage, wallet, nonce):

    storage.save_nonce(wallet, nonce)

    result = storage.consume_nonce(wallet, nonce)

    assert result is True


def test_nonce_replay_rejected(storage, wallet, nonce):

    storage.save_nonce(wallet, nonce)

    first = storage.consume_nonce(wallet, nonce)
    second = storage.consume_nonce(wallet, nonce)

    assert first is True
    assert second is False


def test_nonce_persistence_after_restart(
    tmp_path,
    wallet,
    nonce
):

    database = tmp_path / "persistent.db"

    first_engine = VOINStorageEngine(str(database))

    first_engine.save_nonce(wallet, nonce)

    second_engine = VOINStorageEngine(str(database))

    result = second_engine.consume_nonce(
        wallet,
        nonce
    )

    assert result is True

    assert second_engine.consume_nonce(
        wallet,
        nonce
    ) is False


def test_challenge_storage(storage, wallet, nonce):

    challenge_id = "challenge_test_001"
    message = "VOIN Authentication Test"

    result = storage.save_challenge(
        challenge_id,
        wallet,
        nonce,
        message,
        int(time.time()) + 300
    )

    assert result is True

    challenge = storage.get_challenge(challenge_id)

    assert challenge is not None
    assert challenge["wallet_address"] == wallet.lower()
    assert challenge["message"] == message
    assert challenge["used"] == 0


def test_challenge_persistence_after_restart(
    tmp_path,
    wallet,
    nonce
):

    database = tmp_path / "challenge.db"

    first_engine = VOINStorageEngine(str(database))

    first_engine.save_challenge(
        "persistent_challenge",
        wallet,
        nonce,
        "VOIN Persistent Test",
        int(time.time()) + 300
    )

    second_engine = VOINStorageEngine(str(database))

    challenge = second_engine.get_challenge(
        "persistent_challenge"
    )

    assert challenge is not None
    assert challenge["used"] == 0


def test_challenge_consumption(storage, wallet, nonce):

    challenge_id = "challenge_consume"

    storage.save_challenge(
        challenge_id,
        wallet,
        nonce,
        "VOIN Challenge",
        int(time.time()) + 300
    )

    result = storage.consume_challenge(
        challenge_id,
        wallet
    )

    assert result is True


def test_challenge_replay_rejected(storage, wallet, nonce):

    challenge_id = "challenge_replay"

    storage.save_challenge(
        challenge_id,
        wallet,
        nonce,
        "VOIN Replay Test",
        int(time.time()) + 300
    )

    first = storage.consume_challenge(
        challenge_id,
        wallet
    )

    second = storage.consume_challenge(
        challenge_id,
        wallet
    )

    assert first is True
    assert second is False


def test_wrong_wallet_cannot_consume_challenge(
    storage,
    wallet,
    nonce
):

    storage.save_challenge(
        "challenge_wallet_test",
        wallet,
        nonce,
        "VOIN Wallet Test",
        int(time.time()) + 300
    )

    result = storage.consume_challenge(
        "challenge_wallet_test",
        "0x9999999999999999999999999999999999999999"
    )

    assert result is False


def test_atomic_challenge_consumption(
    storage,
    wallet,
    nonce
):

    challenge_id = "challenge_atomic"

    storage.save_challenge(
        challenge_id,
        wallet,
        nonce,
        "VOIN Atomic Test",
        int(time.time()) + 300
    )

    def consume():
        return storage.consume_challenge(
            challenge_id,
            wallet
        )

    with ThreadPoolExecutor(max_workers=5) as executor:

        results = list(
            executor.map(
                lambda _: consume(),
                range(5)
            )
        )

    assert results.count(True) == 1
    assert results.count(False) == 4


def test_security_audit_logging(storage, wallet):

    storage.log_event(
        "TEST_SECURITY_EVENT",
        wallet,
        "test_reference",
        {"source": "pytest"}
    )

    events = storage.get_security_events()

    assert len(events) >= 1

    event = events[0]

    assert event["event_type"] == "TEST_SECURITY_EVENT"
    assert event["wallet_address"] == wallet.lower()


def test_invalid_nonce_rejected(storage, wallet):

    with pytest.raises(ValueError):
        storage.save_nonce(wallet, "")


def test_invalid_event_limit_rejected(storage):

    with pytest.raises(ValueError):
        storage.get_security_events(0)
