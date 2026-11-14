"""
VOIN SECURITY HARDENING TEST SUITE V1.1

Tests additional security protections:
- Invalid signatures
- Expired challenges
- Challenge replay
- Nonce replay
- Nonce mismatch
- Invalid wallet addresses
"""

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

    integration.challenge_engine.challenges[
        challenge_id
    ]["expires_at"] = 0

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

    integration.nonce_engine.wallet_nonces[
        wallet.address.lower()
    ]["nonce"] = "0" * 64

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
        challenge_id
    )

    second = integration.challenge_engine.consume_challenge(
        challenge_id
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
