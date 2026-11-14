"""
VOIN SECURITY INTEGRATION TEST SUITE V1.0

Tests integrated wallet authentication,
challenge validation, digital signatures,
nonce protection and replay prevention.
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


def test_integration_engine_creation(integration):
    assert integration is not None


def test_engine_information(integration):
    info = integration.engine_info()

    assert info["engine"] == "VOIN Security Integration"
    assert info["wallet_verification"] is True
    assert info["challenge_validation"] is True
    assert info["digital_signature"] is True
    assert info["nonce_protection"] is True
    assert info["replay_protection"] is True


def test_create_authentication(integration, wallet):

    result = integration.create_authentication(
        wallet.address
    )

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

    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=wallet.key
    )

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

    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=wrong_wallet.key
    )

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

    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=wallet.key
    )

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


def test_nonce_consumed_after_authentication(integration, wallet):

    challenge = integration.create_authentication(
        wallet.address
    )

    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=wallet.key
    )

    integration.verify_authentication(
        challenge["challenge_id"],
        wallet.address,
        signed.signature
    )

    nonce_record = integration.nonce_engine.wallet_nonces[
        wallet.address.lower()
    ]

    assert nonce_record["used"] is True
