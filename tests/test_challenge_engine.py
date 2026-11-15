import re
import sqlite3
import time

import pytest

from security.challenge import VOINChallengeEngine
from security.storage import VOINStorageEngine


WALLET = "0x1234567890abcdef1234567890abcdef12345678"
VALID_NONCE = "b" * 64


@pytest.fixture
def storage(tmp_path):
    engine = VOINStorageEngine(
        tmp_path / "challenge_engine_test.db"
    )
    yield engine
    engine.close()


@pytest.fixture
def challenge_engine(storage):
    return VOINChallengeEngine(
        expiry_seconds=300,
        storage=storage,
    )


def test_challenge_engine_version(challenge_engine):
    assert challenge_engine.VERSION == "1.3.1"


@pytest.mark.parametrize(
    "expiry",
    [0, -1, True, False, 1.5, "300", None],
)
def test_invalid_expiry_rejected(storage, expiry):
    with pytest.raises((ValueError, TypeError)):
        VOINChallengeEngine(
            expiry_seconds=expiry,
            storage=storage,
        )


def test_valid_expiry_accepted(storage):
    engine = VOINChallengeEngine(
        expiry_seconds=300,
        storage=storage,
    )

    assert engine.expiry_seconds == 300


def test_nonce_generation(challenge_engine):
    result = challenge_engine.create_challenge(WALLET)

    assert result["success"] is True
    assert isinstance(result["nonce"], str)
    assert len(result["nonce"]) == 64
    assert re.fullmatch(r"[a-fA-F0-9]{64}", result["nonce"])


@pytest.mark.parametrize(
    "nonce",
    [
        "",
        "abc",
        "g" * 64,
        "b" * 63,
        "b" * 65,
        None,
    ],
)
def test_invalid_nonce_rejected(challenge_engine, nonce):
    if nonce is None:
        return

    with pytest.raises((ValueError, TypeError)):
        challenge_engine.create_challenge(
            WALLET,
            nonce=nonce,
        )


def test_valid_custom_nonce_accepted(challenge_engine):
    result = challenge_engine.create_challenge(
        WALLET,
        nonce=VALID_NONCE,
    )

    assert result["success"] is True
    assert result["nonce"] == VALID_NONCE


def test_challenge_creation_persists_wallet(
    challenge_engine,
    storage,
):
    result = challenge_engine.create_challenge(WALLET)

    assert result["success"] is True

    challenge = storage.get_challenge(
        result["challenge_id"]
    )

    assert challenge is not None
    assert challenge["wallet_address"].lower() == WALLET.lower()
    assert challenge["used"] == 0


def test_challenge_message_contains_nonce(challenge_engine):
    result = challenge_engine.create_challenge(WALLET)

    assert result["nonce"] in result["message"]
    assert result["challenge_id"] in result["message"]
    assert WALLET in result["message"]


def test_challenge_validation_success(challenge_engine):
    result = challenge_engine.create_challenge(WALLET)

    assert challenge_engine.validate_challenge(
        result["challenge_id"],
        WALLET,
    ) is True


def test_challenge_wallet_comparison_case_insensitive(
    challenge_engine,
):
    result = challenge_engine.create_challenge(WALLET)

    assert challenge_engine.validate_challenge(
        result["challenge_id"],
        WALLET.upper(),
    ) is True


def test_challenge_wrong_wallet_rejected(challenge_engine):
    result = challenge_engine.create_challenge(WALLET)

    wrong_wallet = "0x9999999999999999999999999999999999999999"

    assert challenge_engine.validate_challenge(
        result["challenge_id"],
        wrong_wallet,
    ) is False


def test_missing_challenge_rejected(challenge_engine):
    assert challenge_engine.validate_challenge(
        "f" * 64,
        WALLET,
    ) is False


def test_expired_challenge_rejected(
    challenge_engine,
    storage,
):
    result = challenge_engine.create_challenge(WALLET)

    with storage._connect() as connection:
        connection.execute(
            """
            UPDATE challenges
            SET expires_at = ?
            WHERE challenge_id = ?
            """,
            (
                int(time.time()) - 10,
                result["challenge_id"],
            ),
        )

    assert challenge_engine.validate_challenge(
        result["challenge_id"],
        WALLET,
    ) is False


def test_consumed_challenge_cannot_be_validated(
    challenge_engine,
):
    result = challenge_engine.create_challenge(WALLET)

    consumed = challenge_engine.consume_challenge(
        result["challenge_id"],
        WALLET,
    )

    assert consumed is True

    assert challenge_engine.validate_challenge(
        result["challenge_id"],
        WALLET,
    ) is False


def test_challenge_consumption_replay_rejected(
    challenge_engine,
):
    result = challenge_engine.create_challenge(WALLET)

    first = challenge_engine.consume_challenge(
        result["challenge_id"],
        WALLET,
    )

    second = challenge_engine.consume_challenge(
        result["challenge_id"],
        WALLET,
    )

    assert first is True
    assert second is False


def test_consume_challenge_without_wallet(
    challenge_engine,
):
    result = challenge_engine.create_challenge(WALLET)

    assert challenge_engine.consume_challenge(
        result["challenge_id"]
    ) is True


def test_storage_failure_propagates(
    challenge_engine,
    storage,
    monkeypatch,
):
    def failing_create(*args, **kwargs):
        raise RuntimeError("Simulated storage failure")

    monkeypatch.setattr(
        storage,
        "create_challenge_atomic",
        failing_create,
    )

    with pytest.raises(RuntimeError):
        challenge_engine.create_challenge(WALLET)


def test_atomic_creation_failure_rolls_back(
    challenge_engine,
    storage,
):
    with storage._connect() as connection:
        connection.execute(
            """
            CREATE TRIGGER fail_challenge_insert
            BEFORE INSERT ON challenges
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'Simulated challenge insert failure'
                );
            END;
            """
        )

    with pytest.raises(sqlite3.IntegrityError):
        challenge_engine.create_challenge(
            WALLET,
            nonce=VALID_NONCE,
        )

    with storage._connect() as connection:
        nonce_count = connection.execute(
            "SELECT COUNT(*) FROM nonces"
        ).fetchone()[0]

        challenge_count = connection.execute(
            "SELECT COUNT(*) FROM challenges"
        ).fetchone()[0]

    assert nonce_count == 0
    assert challenge_count == 0
