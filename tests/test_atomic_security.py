"""
VOIN ATOMIC SECURITY HARDENING TESTS V1.0

Tests:
- Atomic challenge and nonce consumption
- Rollback when nonce is missing
- Rollback when challenge is invalid
- Replay prevention
- Concurrent authentication protection
"""

import time
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from security.storage import VOINStorageEngine


@pytest.fixture
def storage(tmp_path):
    db_path = tmp_path / "atomic_security.db"
    return VOINStorageEngine(str(db_path))


@pytest.fixture
def authentication_data(storage):
    wallet = "0x1234567890abcdef1234567890abcdef12345678"
    nonce = "test_nonce_123456789"
    challenge_id = "challenge_test_001"

    storage.save_nonce(wallet, nonce)

    storage.save_challenge(
        challenge_id=challenge_id,
        wallet_address=wallet,
        nonce=nonce,
        message="VOIN authentication test",
        expires_at=int(time.time()) + 300
    )

    return wallet, nonce, challenge_id


def get_security_state(storage, wallet, nonce, challenge_id):
    nonce_hash = storage._hash_nonce(nonce)

    with storage._connect() as connection:

        challenge = connection.execute("""
            SELECT used
            FROM challenges
            WHERE challenge_id = ?
        """, (challenge_id,)).fetchone()

        nonce_record = connection.execute("""
            SELECT used
            FROM nonces
            WHERE wallet_address = ?
            AND nonce_hash = ?
        """, (
            wallet.lower(),
            nonce_hash
        )).fetchone()

    return (
        None if challenge is None else challenge["used"],
        None if nonce_record is None else nonce_record["used"]
    )


def test_atomic_authentication_success(
    storage,
    authentication_data
):
    wallet, nonce, challenge_id = authentication_data

    result = storage.consume_authentication(
        challenge_id,
        wallet,
        nonce
    )

    assert result is True

    challenge_used, nonce_used = get_security_state(
        storage,
        wallet,
        nonce,
        challenge_id
    )

    assert challenge_used == 1
    assert nonce_used == 1


def test_missing_nonce_rolls_back_challenge(
    storage,
    authentication_data
):
    wallet, nonce, challenge_id = authentication_data

    result = storage.consume_authentication(
        challenge_id,
        wallet,
        "wrong_nonce"
    )

    assert result is False

    challenge_used, nonce_used = get_security_state(
        storage,
        wallet,
        nonce,
        challenge_id
    )

    assert challenge_used == 0
    assert nonce_used == 0


def test_missing_challenge_does_not_consume_nonce(
    storage,
    authentication_data
):
    wallet, nonce, _ = authentication_data

    result = storage.consume_authentication(
        "invalid_challenge",
        wallet,
        nonce
    )

    assert result is False

    nonce_hash = storage._hash_nonce(nonce)

    with storage._connect() as connection:
        row = connection.execute("""
            SELECT used
            FROM nonces
            WHERE wallet_address = ?
            AND nonce_hash = ?
        """, (
            wallet.lower(),
            nonce_hash
        )).fetchone()

    assert row["used"] == 0


def test_replay_authentication_is_rejected(
    storage,
    authentication_data
):
    wallet, nonce, challenge_id = authentication_data

    first_result = storage.consume_authentication(
        challenge_id,
        wallet,
        nonce
    )

    second_result = storage.consume_authentication(
        challenge_id,
        wallet,
        nonce
    )

    assert first_result is True
    assert second_result is False


def test_expired_challenge_does_not_consume_nonce(
    storage,
    authentication_data
):
    wallet, nonce, challenge_id = authentication_data

    with storage._connect() as connection:
        connection.execute("""
            UPDATE challenges
            SET expires_at = 0
            WHERE challenge_id = ?
        """, (challenge_id,))

    result = storage.consume_authentication(
        challenge_id,
        wallet,
        nonce
    )

    assert result is False

    challenge_used, nonce_used = get_security_state(
        storage,
        wallet,
        nonce,
        challenge_id
    )

    assert challenge_used == 0
    assert nonce_used == 0


def test_concurrent_authentication_only_succeeds_once(
    storage,
    authentication_data
):
    wallet, nonce, challenge_id = authentication_data

    barrier = threading.Barrier(2)

    def attempt_authentication():
        barrier.wait()

        return storage.consume_authentication(
            challenge_id,
            wallet,
            nonce
        )

    with ThreadPoolExecutor(max_workers=2) as executor:

        futures = [
            executor.submit(attempt_authentication)
            for _ in range(2)
        ]

        results = [
            future.result()
            for future in futures
        ]

    assert results.count(True) == 1
    assert results.count(False) == 1

    challenge_used, nonce_used = get_security_state(
        storage,
        wallet,
        nonce,
        challenge_id
    )

    assert challenge_used == 1
    assert nonce_used == 1


def test_atomic_consumption_creates_audit_event(
    storage,
    authentication_data
):
    wallet, nonce, challenge_id = authentication_data

    storage.consume_authentication(
        challenge_id,
        wallet,
        nonce
    )

    events = storage.get_security_events(limit=20)

    matching_events = [
        event for event in events
        if event["event_type"] == "AUTHENTICATION_CONSUMED"
        and event["reference_id"] == challenge_id
    ]

    assert len(matching_events) == 1
