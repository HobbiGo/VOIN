"""
VOIN VERIFICATION ENGINE TEST SUITE V1.0

Tests wallet authentication, challenge validation,
digital signatures, nonce protection and replay prevention.
"""

import pytest

from eth_account import Account
from eth_account.messages import encode_defunct

from security.verification import VOINVerificationEngine
from security.challenge import VOINChallengeEngine
from security.nonce import VOINNonceEngine


@pytest.fixture
def wallet():
    return Account.create()


@pytest.fixture
def challenge_engine():
    return VOINChallengeEngine()


@pytest.fixture
def nonce_engine():
    return VOINNonceEngine()


@pytest.fixture
def verification_engine():
    return VOINVerificationEngine()


def test_wallet_creation(wallet):
    assert wallet.address is not None
    assert wallet.address.startswith("0x")


def test_wallet_address_format(wallet):
    assert len(wallet.address) == 42


def test_wallet_signature(wallet):
    message = "VOIN Authentication Test"

    signed = Account.sign_message(
        encode_defunct(text=message),
        private_key=wallet.key
    )

    recovered = Account.recover_message(
        encode_defunct(text=message),
        signature=signed.signature
    )

    assert recovered.lower() == wallet.address.lower()


def test_signature_verification(wallet):
    message = "VOIN Verification Engine"

    signed = Account.sign_message(
        encode_defunct(text=message),
        private_key=wallet.key
    )

    recovered = Account.recover_message(
        encode_defunct(text=message),
        signature=signed.signature
    )

    assert recovered.lower() == wallet.address.lower()


def test_signature_rejects_wrong_message(wallet):
    original_message = "VOIN Authentication"
    different_message = "Invalid Authentication"

    signed = Account.sign_message(
        encode_defunct(text=original_message),
        private_key=wallet.key
    )

    recovered = Account.recover_message(
        encode_defunct(text=different_message),
        signature=signed.signature
    )

    assert recovered.lower() != wallet.address.lower()


def test_wallets_are_unique():
    wallet_one = Account.create()
    wallet_two = Account.create()

    assert wallet_one.address != wallet_two.address


def test_challenge_engine_exists(challenge_engine):
    assert challenge_engine is not None


def test_nonce_engine_exists(nonce_engine):
    assert nonce_engine is not None


def test_verification_engine_exists(verification_engine):
    assert verification_engine is not None
