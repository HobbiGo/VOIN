"""
VOIN SECURITY AUDIT INTEGRATION TEST SUITE V1.0

Tests:
- Wallet authentication
- Challenge validation
- Digital signatures
- Nonce protection
- Replay prevention
- Automatic security audit
- Audit persistence
"""

import time

import pytest

from eth_account import Account
from eth_account.messages import encode_defunct

from security.integration import VOINSecurityIntegration
from security.storage import VOINStorageEngine
from security.audit import VOINAuditEngine


@pytest.fixture
def wallet():
    return Account.create()


@pytest.fixture
def integration():
    return VOINSecurityIntegration()


def sign_challenge(challenge, wallet):

    return Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=wallet.key
    )


def test_integration_engine_creation(integration):
    assert integration is not None
    assert integration.audit_engine is not None


def test_engine_information(integration):

    info = integration.engine_info()

    assert info["engine"] == "VOIN Security Integration"
    assert info["wallet_verification"] is True
    assert info["challenge_validation"] is True
    assert info["digital_signature"] is True
    assert info["nonce_protection"] is True
    assert info["replay_protection"] is True
    assert info["security_audit"] is True
    assert info["automatic_audit_logging"] is True


def test_create_authentication(integration, wallet):

    result = integration.create_authentication(wallet.address)

    assert result["success"] is True
    assert result["challenge_id"]
    assert result["nonce"]
    assert result["message"]


def test_invalid_wallet_rejected(integration):

    result = integration.create_authentication(
        "INVALID_WALLET"
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_ADDRESS"


def test_successful_authentication(integration, wallet):

    challenge = integration.create_authentication(
        wallet.address
    )

    signed = sign_challenge(challenge, wallet)

    result = integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    assert result["success"] is True
    assert result["status"] == "AUTHENTICATION_SUCCESSFUL"


def test_wrong_signature_rejected(integration, wallet):

    challenge = integration.create_authentication(
        wallet.address
    )

    wrong_wallet = Account.create()

    signed = sign_challenge(challenge, wrong_wallet)

    result = integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    assert result["success"] is False


def test_replay_authentication_rejected(integration, wallet):

    challenge = integration.create_authentication(
        wallet.address
    )

    signed = sign_challenge(challenge, wallet)

    first_result = integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    second_result = integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    assert first_result["success"] is True
    assert second_result["success"] is False


def test_nonce_consumed_after_authentication(
    integration,
    wallet
):

    challenge = integration.create_authentication(
        wallet.address
    )

    signed = sign_challenge(challenge, wallet)

    result = integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    assert result["success"] is True

    storage = integration.challenge_engine.storage

    nonce_hash = storage._hash_nonce(challenge["nonce"])

    with storage._connect() as connection:

        nonce_record = connection.execute(
            """
            SELECT used
            FROM nonces
            WHERE wallet_address = ?
            AND nonce_hash = ?
            """,
            (
                wallet.address.lower(),
                nonce_hash
            )
        ).fetchone()

    assert nonce_record is not None
    assert nonce_record["used"] == 1


def test_successful_authentication_is_audited(
    integration,
    wallet
):

    challenge = integration.create_authentication(
        wallet.address
    )

    signed = sign_challenge(challenge, wallet)

    integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    events = integration.audit_engine.get_wallet_events(
        wallet.address
    )

    matching = [
        event for event in events
        if event["event_type"] == "AUTHENTICATION_SUCCESS"
        and event["reference_id"] == challenge["challenge_id"]
    ]

    assert len(matching) == 1


def test_failed_signature_is_audited(
    integration,
    wallet
):

    challenge = integration.create_authentication(
        wallet.address
    )

    wrong_wallet = Account.create()
    signed = sign_challenge(challenge, wrong_wallet)

    integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    events = integration.audit_engine.get_wallet_events(
        wallet.address
    )

    matching = [
        event for event in events
        if event["event_type"] == "AUTHENTICATION_FAILED"
        and event["reference_id"] == challenge["challenge_id"]
    ]

    assert len(matching) == 1


def test_replay_attempt_is_audited(
    integration,
    wallet
):

    challenge = integration.create_authentication(
        wallet.address
    )

    signed = sign_challenge(challenge, wallet)

    integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    events = integration.audit_engine.get_wallet_events(
        wallet.address
    )

    matching = [
        event for event in events
        if event["event_type"] == "REPLAY_ATTEMPT"
        and event["reference_id"] == challenge["challenge_id"]
    ]

    assert len(matching) == 1


def test_expired_challenge_is_audited(
    integration,
    wallet
):

    challenge = integration.create_authentication(
        wallet.address
    )

    storage = integration.challenge_engine.storage

    with storage._connect() as connection:
        connection.execute(
            """
            UPDATE challenges
            SET expires_at = 0
            WHERE challenge_id = ?
            """,
            (challenge["challenge_id"],)
        )

    result = integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        "invalid_signature"
    )

    assert result["success"] is False

    events = integration.audit_engine.get_wallet_events(
        wallet.address
    )

    matching = [
        event for event in events
        if event["event_type"] == "EXPIRED_CHALLENGE"
        and event["reference_id"] == challenge["challenge_id"]
    ]

    assert len(matching) == 1


def test_audit_survives_storage_reinitialization(
    integration,
    wallet
):

    challenge = integration.create_authentication(
        wallet.address
    )

    signed = sign_challenge(challenge, wallet)

    integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    original_storage = integration.challenge_engine.storage

    reopened_storage = VOINStorageEngine(
        original_storage.database_path
    )

    reopened_audit = VOINAuditEngine(
        storage=reopened_storage
    )

    events = reopened_audit.get_wallet_events(
        wallet.address
    )

    matching = [
        event for event in events
        if event["event_type"] == "AUTHENTICATION_SUCCESS"
        and event["reference_id"] == challenge["challenge_id"]
    ]

    assert len(matching) == 1
