"""
VOIN SECURITY HARDENING TEST SUITE V1.2

Tests additional security protections:
- Invalid signatures
- Expired challenges
- Challenge replay
- Nonce replay
- Nonce mismatch
- Invalid wallet addresses
"""

import hashlib

import pytest

from eth_account import Account
from eth_account.messages import encode_defunct

from security.integration import VOINSecurityIntegration


@pytest.fixture
def wallet():
    return Account.create()


@pytest.fixture
def integration():
    return VOINSecurityIntegration()


def test_invalid_wallet_address(integration):

    result = integration.create_authentication(
        "INVALID_ADDRESS"
    )

    assert result["success"] is False


def test_invalid_signature(integration, wallet):

    challenge = integration.create_authentication(
        wallet.address
    )

    result = integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        "invalid_signature"
    )

    assert result["success"] is False


def test_expired_challenge(integration, wallet):

    challenge = integration.create_authentication(
        wallet.address
    )

    challenge_id = challenge["challenge_id"]

    storage = integration.challenge_engine.storage

    with storage._connect() as connection:
        connection.execute(
            """
            UPDATE challenges
            SET expires_at = 0
            WHERE challenge_id = ?
            """,
            (challenge_id,)
        )

    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=wallet.key
    )

    result = integration.verify_authentication(
        challenge_id,
        wallet.address,
        signed.signature
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_OR_EXPIRED_CHALLENGE"


def test_nonce_mismatch(integration, wallet):

    challenge = integration.create_authentication(
        wallet.address
    )

    nonce = challenge["nonce"]

    storage = integration.challenge_engine.storage

    original_hash = hashlib.sha256(
        nonce.encode()
    ).hexdigest()

    wrong_hash = hashlib.sha256(
        ("wrong-" + nonce).encode()
    ).hexdigest()

    with storage._connect() as connection:
        connection.execute(
            """
            UPDATE nonces
            SET nonce_hash = ?
            WHERE wallet_address = ?
            AND nonce_hash = ?
            """,
            (
                wrong_hash,
                wallet.address.lower(),
                original_hash
            )
        )

    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=wallet.key
    )

    result = integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    assert result["success"] is False
    assert result["status"] == "NONCE_MISMATCH"


def test_nonce_replay_rejected(integration, wallet):

    challenge = integration.create_authentication(
        wallet.address
    )

    nonce = challenge["nonce"]

    first = integration.nonce_engine.verify_nonce(
        wallet.address,
        nonce
    )

    second = integration.nonce_engine.verify_nonce(
        wallet.address,
        nonce
    )

    assert first is True
    assert second is False


def test_challenge_replay_rejected(integration, wallet):

    challenge = integration.create_authentication(
        wallet.address
    )

    challenge_id = challenge["challenge_id"]

    first = integration.challenge_engine.consume_challenge(
        challenge_id,
        wallet.address
    )

    second = integration.challenge_engine.consume_challenge(
        challenge_id,
        wallet.address
    )

    assert first is True
    assert second is False


def test_wallet_authentication_replay(integration, wallet):

    challenge = integration.create_authentication(
        wallet.address
    )

    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=wallet.key
    )

    first = integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    second = integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    assert first["success"] is True
    assert second["success"] is False
