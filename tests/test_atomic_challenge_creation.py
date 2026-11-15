"""
VOIN ATOMIC CHALLENGE CREATION TEST SUITE V1.0

Tests:
- Atomic nonce and challenge creation
- Nonce persistence
- Challenge persistence
- Duplicate nonce rejection
- Duplicate challenge ID rejection
- Transaction rollback
- Security event rollback
"""

import sqlite3
import time

import pytest

from security.storage import VOINStorageEngine


@pytest.fixture
def storage(tmp_path):
    return VOINStorageEngine(
        tmp_path / "atomic_challenge_test.db"
    )


@pytest.fixture
def challenge_data():
    return {
        "challenge_id": "a" * 64,
        "wallet_address": "0x1234567890abcdef1234567890abcdef12345678",
        "nonce": "b" * 64,
        "message": "VOIN WALLET AUTHENTICATION TEST",
        "expires_at": int(time.time()) + 300
    }


def create_atomic_challenge(storage, data):

    return storage.create_challenge_atomic(
        data["challenge_id"],
        data["wallet_address"],
        data["nonce"],
        data["message"],
        data["expires_at"]
    )


def get_table_count(storage, table_name):

    allowed_tables = {
        "nonces",
        "challenges",
        "security_events"
    }

    if table_name not in allowed_tables:
        raise ValueError("Invalid table name")

    with storage._connect() as connection:

        result = connection.execute(
            f"SELECT COUNT(*) FROM {table_name}"
        ).fetchone()

        return result[0]


# ==================================================
# ATOMIC CREATION
# ==================================================

def test_atomic_challenge_creation_success(
    storage,
    challenge_data
):

    result = create_atomic_challenge(
        storage,
        challenge_data
    )

    challenge = storage.get_challenge(
        challenge_data["challenge_id"]
    )

    assert challenge is not None

    assert (
        challenge["wallet_address"].lower()
        == challenge_data["wallet_address"].lower()
    )

    assert challenge["message"] == challenge_data["message"]

    assert get_table_count(storage, "nonces") == 1
    assert get_table_count(storage, "challenges") == 1

    assert get_table_count(storage, "security_events") == 3


# ==================================================
# DUPLICATE NONCE PROTECTION
# ==================================================

def test_duplicate_nonce_rejected_without_partial_data(
    storage,
    challenge_data
):

    create_atomic_challenge(
        storage,
        challenge_data
    )

    second_challenge = dict(challenge_data)

    second_challenge["challenge_id"] = "c" * 64

    with pytest.raises(sqlite3.IntegrityError):

        create_atomic_challenge(
            storage,
            second_challenge
        )

    assert get_table_count(storage, "nonces") == 1
    assert get_table_count(storage, "challenges") == 1
    assert get_table_count(storage, "security_events") == 3

    assert (
        storage.get_challenge("c" * 64)
        is None
    )


# ==================================================
# DUPLICATE CHALLENGE ID PROTECTION
# ==================================================

def test_duplicate_challenge_id_rolls_back_nonce(
    storage,
    challenge_data
):

    create_atomic_challenge(
        storage,
        challenge_data
    )

    second_challenge = dict(challenge_data)

    second_challenge["nonce"] = "d" * 64

    with pytest.raises(sqlite3.IntegrityError):

        create_atomic_challenge(
            storage,
            second_challenge
        )

    assert get_table_count(storage, "nonces") == 1
    assert get_table_count(storage, "challenges") == 1
    assert get_table_count(storage, "security_events") == 3


# ==================================================
# EVENT FAILURE ROLLBACK
# ==================================================

def test_event_failure_rolls_back_entire_transaction(
    storage,
    challenge_data
):

    with storage._connect() as connection:

        connection.execute("""
            CREATE TRIGGER fail_atomic_challenge_event
            BEFORE INSERT ON security_events
            WHEN NEW.event_type = 'CHALLENGE_CREATED_ATOMIC'
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'forced atomic event failure'
                );
            END;
        """)

    with pytest.raises(sqlite3.IntegrityError):

        create_atomic_challenge(
            storage,
            challenge_data
        )

    assert get_table_count(storage, "nonces") == 0
    assert get_table_count(storage, "challenges") == 0
    assert get_table_count(storage, "security_events") == 0

    assert (
        storage.get_challenge(
            challenge_data["challenge_id"]
        )
        is None
    )


# ==================================================
# CHALLENGE RETRIEVAL
# ==================================================

def test_atomic_challenge_can_be_retrieved(
    storage,
    challenge_data
):

    create_atomic_challenge(
        storage,
        challenge_data
    )

    challenge = storage.get_challenge(
        challenge_data["challenge_id"]
    )

    assert challenge is not None
    assert challenge["used"] is False


# ==================================================
# ENGINE VERSION
# ==================================================

def test_storage_engine_version():

    assert VOINStorageEngine.VERSION == "1.4.0"
