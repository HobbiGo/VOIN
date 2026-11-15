import re

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from security.storage import VOINStorageEngine
from security.verification import VOINVerificationEngine


@pytest.fixture
def storage(tmp_path):
    database_path = tmp_path / "verification_test.db"

    engine = VOINStorageEngine(
        database_path=str(database_path)
    )

    yield engine

    engine.close()


@pytest.fixture
def wallet():
    return Account.create()


@pytest.fixture
def verification(storage):
    return VOINVerificationEngine(
        expiry_seconds=300,
        storage=storage
    )


def create_signed_challenge(verification, wallet):
    result = verification.create_verification_challenge(
        wallet.address
    )

    assert result["success"] is True

    challenge_id = result["challenge_id"]

    challenge = verification.challenge_engine.storage.get_challenge(
        challenge_id
    )

    assert challenge is not None

    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=wallet.key
    )

    return challenge_id, signed.signature.hex(), challenge


def test_engine_creation(verification):
    assert verification.VERSION == "1.1.0"
    assert verification.challenge_engine is not None
    assert verification.signature_engine is not None


def test_engine_info():
    info = VOINVerificationEngine.engine_info()

    assert info["engine"] == "VOIN Verification Engine"
    assert info["version"] == "1.1.0"
    assert info["challenge_verification"] is True
    assert info["signature_verification"] is True
    assert info["persistent_storage"] is True
    assert info["replay_protection"] is True


def test_invalid_wallet_address(verification):
    result = verification.create_verification_challenge(
        "invalid-wallet"
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_ADDRESS"


def test_create_verification_challenge(verification, wallet):
    result = verification.create_verification_challenge(
        wallet.address
    )

    assert result["success"] is True
    assert result["challenge_id"]
    assert result["message"]
    assert result["nonce"]


def test_challenge_persisted_in_storage(verification, wallet):
    result = verification.create_verification_challenge(
        wallet.address
    )

    challenge = verification.challenge_engine.storage.get_challenge(
        result["challenge_id"]
    )

    assert challenge is not None
    assert challenge["wallet_address"].lower() == wallet.address.lower()
    assert challenge["message"]


def test_invalid_challenge_rejected(verification, wallet):
    result = verification.verify_wallet(
        challenge_id="invalid-challenge",
        wallet_address=wallet.address,
        signature="0x" + ("00" * 65)
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_OR_EXPIRED_CHALLENGE"


def test_missing_challenge_after_validation(
    verification,
    wallet,
    monkeypatch
):
    monkeypatch.setattr(
        verification.challenge_engine,
        "validate_challenge",
        lambda challenge_id, wallet_address: True
    )

    monkeypatch.setattr(
        verification.challenge_engine.storage,
        "get_challenge",
        lambda challenge_id: None
    )

    result = verification.verify_wallet(
        challenge_id="missing-challenge",
        wallet_address=wallet.address,
        signature="0x" + ("00" * 65)
    )

    assert result["success"] is False
    assert result["status"] == "CHALLENGE_NOT_FOUND"


def test_invalid_signature_rejected(verification, wallet):
    challenge_id, _, _ = create_signed_challenge(
        verification,
        wallet
    )

    result = verification.verify_wallet(
        challenge_id=challenge_id,
        wallet_address=wallet.address,
        signature="0x" + ("00" * 65)
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_SIGNATURE"


def test_signature_from_wrong_wallet_rejected(
    verification,
    wallet
):
    other_wallet = Account.create()

    challenge_id = verification.create_verification_challenge(
        wallet.address
    )["challenge_id"]

    challenge = verification.challenge_engine.storage.get_challenge(
        challenge_id
    )

    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=other_wallet.key
    )

    result = verification.verify_wallet(
        challenge_id=challenge_id,
        wallet_address=wallet.address,
        signature=signed.signature.hex()
    )

    assert result["success"] is False
    assert result["status"] == "SIGNER_MISMATCH"


def test_successful_wallet_verification(verification, wallet):
    challenge_id, signature, _ = create_signed_challenge(
        verification,
        wallet
    )

    result = verification.verify_wallet(
        challenge_id=challenge_id,
        wallet_address=wallet.address,
        signature=signature
    )

    assert result["success"] is True
    assert result["status"] == "WALLET_VERIFIED"
    assert result["wallet_address"].lower() == wallet.address.lower()
    assert result["challenge_id"] == challenge_id
    assert result["version"] == "1.1.0"


def test_challenge_consumed_after_successful_verification(
    verification,
    wallet
):
    challenge_id, signature, _ = create_signed_challenge(
        verification,
        wallet
    )

    result = verification.verify_wallet(
        challenge_id=challenge_id,
        wallet_address=wallet.address,
        signature=signature
    )

    assert result["success"] is True

    challenge = verification.challenge_engine.storage.get_challenge(
        challenge_id
    )

    assert challenge["used"] is True


def test_replay_attempt_rejected(verification, wallet):
    challenge_id, signature, _ = create_signed_challenge(
        verification,
        wallet
    )

    first_result = verification.verify_wallet(
        challenge_id=challenge_id,
        wallet_address=wallet.address,
        signature=signature
    )

    second_result = verification.verify_wallet(
        challenge_id=challenge_id,
        wallet_address=wallet.address,
        signature=signature
    )

    assert first_result["success"] is True
    assert second_result["success"] is False
    assert second_result["status"] == "INVALID_OR_EXPIRED_CHALLENGE"


def test_nonce_consumed_after_successful_verification(
    verification,
    wallet
):
    challenge_id, signature, challenge = create_signed_challenge(
        verification,
        wallet
    )

    nonce_match = re.search(
        r"^Nonce: ([a-fA-F0-9]{64})$",
        challenge["message"],
        re.MULTILINE
    )

    assert nonce_match is not None

    nonce = nonce_match.group(1)

    result = verification.verify_wallet(
        challenge_id=challenge_id,
        wallet_address=wallet.address,
        signature=signature
    )

    assert result["success"] is True

    nonce_consumed = verification.challenge_engine.storage.consume_nonce(
        wallet.address,
        nonce
    )

    assert nonce_consumed is False


def test_invalid_wallet_cannot_verify(verification):
    result = verification.verify_wallet(
        challenge_id="any-challenge",
        wallet_address="invalid-wallet",
        signature="0x" + ("00" * 65)
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_ADDRESS"
