import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from security.storage import VOINStorageEngine


@pytest.fixture
def storage(tmp_path):
    db_path = tmp_path / "atomic_authentication_test.db"
    engine = VOINStorageEngine(str(db_path))

    yield engine

    engine.close()


@pytest.fixture
def authentication_data():
    return {
        "challenge_id": "a" * 64,
        "wallet_address": "0x1234567890abcdef1234567890abcdef12345678",
        "nonce": "b" * 64,
        "message": "VOIN authentication test message",
        "expires_at": int(time.time()) + 300,
    }


def create_authentication(storage, data):
    storage.create_challenge_atomic(
        data["challenge_id"],
        data["wallet_address"],
        data["nonce"],
        data["message"],
        data["expires_at"],
    )


def get_authentication_state(storage, data):
    with storage._connect() as connection:
        challenge = connection.execute(
            """
            SELECT used
            FROM challenges
            WHERE challenge_id = ?
            """,
            (data["challenge_id"],),
        ).fetchone()

        nonce = connection.execute(
            """
            SELECT used
            FROM nonces
            WHERE wallet_address = ?
            AND nonce_hash = ?
            """,
            (
                data["wallet_address"].lower(),
                __import__("hashlib").sha256(
                    data["nonce"].encode()
                ).hexdigest(),
            ),
        ).fetchone()

    return (
        None if challenge is None else challenge["used"],
        None if nonce is None else nonce["used"],
    )


def test_atomic_authentication_success(storage, authentication_data):
    create_authentication(storage, authentication_data)

    result = storage.consume_authentication(
        authentication_data["challenge_id"],
        authentication_data["wallet_address"],
        authentication_data["nonce"],
    )

    assert result is True

    challenge_used, nonce_used = get_authentication_state(
        storage, authentication_data
    )

    assert challenge_used == 1
    assert nonce_used == 1


def test_atomic_authentication_replay_rejected(
    storage, authentication_data
):
    create_authentication(storage, authentication_data)

    first_result = storage.consume_authentication(
        authentication_data["challenge_id"],
        authentication_data["wallet_address"],
        authentication_data["nonce"],
    )

    second_result = storage.consume_authentication(
        authentication_data["challenge_id"],
        authentication_data["wallet_address"],
        authentication_data["nonce"],
    )

    assert first_result is True
    assert second_result is False


def test_atomic_authentication_wrong_wallet_rejected(
    storage, authentication_data
):
    create_authentication(storage, authentication_data)

    result = storage.consume_authentication(
        authentication_data["challenge_id"],
        "0x9999999999999999999999999999999999999999",
        authentication_data["nonce"],
    )

    assert result is False

    challenge_used, nonce_used = get_authentication_state(
        storage, authentication_data
    )

    assert challenge_used == 0
    assert nonce_used == 0


def test_atomic_authentication_wrong_nonce_rejected(
    storage, authentication_data
):
    create_authentication(storage, authentication_data)

    result = storage.consume_authentication(
        authentication_data["challenge_id"],
        authentication_data["wallet_address"],
        "c" * 64,
    )

    assert result is False

    challenge_used, nonce_used = get_authentication_state(
        storage, authentication_data
    )

    assert challenge_used == 0
    assert nonce_used == 0


def test_atomic_authentication_expired_challenge_rejected(
    storage, authentication_data
):
    create_authentication(storage, authentication_data)

    with storage._connect() as connection:
        connection.execute(
            """
            UPDATE challenges
            SET expires_at = ?
            WHERE challenge_id = ?
            """,
            (
                int(time.time()) - 10,
                authentication_data["challenge_id"],
            ),
        )

    result = storage.consume_authentication(
        authentication_data["challenge_id"],
        authentication_data["wallet_address"],
        authentication_data["nonce"],
    )

    assert result is False

    challenge_used, nonce_used = get_authentication_state(
        storage, authentication_data
    )

    assert challenge_used == 0
    assert nonce_used == 0


def test_atomic_authentication_event_failure_rolls_back(
    storage, authentication_data
):
    create_authentication(storage, authentication_data)

    with storage._connect() as connection:
        connection.execute(
            """
            CREATE TRIGGER fail_authentication_event
            BEFORE INSERT ON security_events
            WHEN NEW.event_type = 'AUTHENTICATION_CONSUMED'
            BEGIN
                SELECT RAISE(ABORT, 'Simulated event failure');
            END;
            """
        )

    try:
        result = storage.consume_authentication(
            authentication_data["challenge_id"],
            authentication_data["wallet_address"],
            authentication_data["nonce"],
        )
    except sqlite3.IntegrityError:
        result = False

    assert result is False

    challenge_used, nonce_used = get_authentication_state(
        storage, authentication_data
    )

    assert challenge_used == 0
    assert nonce_used == 0


def test_atomic_authentication_concurrent_replay_protection(
    storage, authentication_data
):
    create_authentication(storage, authentication_data)

    def consume():
        return storage.consume_authentication(
            authentication_data["challenge_id"],
            authentication_data["wallet_address"],
            authentication_data["nonce"],
        )

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda _: consume(), range(5)))

    assert results.count(True) == 1
    assert results.count(False) == 4

    challenge_used, nonce_used = get_authentication_state(
        storage, authentication_data
    )

    assert challenge_used == 1
    assert nonce_used == 1
