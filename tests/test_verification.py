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
def verification_engine():
    return VOINVerificationEngine(expiry_seconds=300)


# 1. Challenge Generation Test
def test_challenge_generation(verification_engine, wallet):

    result = verification_engine.create_verification_challenge(
        wallet.address
    )

    assert result["success"] is True
    assert "challenge_id" in result
    assert "message" in result


# 2. Valid Wallet Signature Test
def test_valid_wallet_signature(verification_engine, wallet):

    challenge = verification_engine.create_verification_challenge(
        wallet.address
    )

    message = challenge["message"]

    signature = Account.sign_message(
        encode_defunct(text=message),
        private_key=wallet.key
    ).signature.hex()

    result = verification_engine.verify_wallet(
        challenge["challenge_id"],
        wallet.address,
        signature
    )

    assert result["success"] is True
    assert result["status"] == "WALLET_VERIFIED"


# 3. Invalid Wallet Test
def test_invalid_wallet(verification_engine):

    result = verification_engine.create_verification_challenge(
        "INVALID_WALLET"
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_ADDRESS"


# 4. Invalid Signature Test
def test_invalid_signature(verification_engine, wallet):

    challenge = verification_engine.create_verification_challenge(
        wallet.address
    )

    result = verification_engine.verify_wallet(
        challenge["challenge_id"],
        wallet.address,
        "invalid_signature"
    )

    assert result["success"] is False


# 5. Replay Protection Test
def test_replay_protection(verification_engine, wallet):

    challenge = verification_engine.create_verification_challenge(
        wallet.address
    )

    signature = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=wallet.key
    ).signature.hex()

    first_result = verification_engine.verify_wallet(
        challenge["challenge_id"],
        wallet.address,
        signature
    )

    second_result = verification_engine.verify_wallet(
        challenge["challenge_id"],
        wallet.address,
        signature
    )

    assert first_result["success"] is True
    assert second_result["success"] is False


# 6. Challenge Expiration Test
def test_challenge_expiration(verification_engine, wallet):

    challenge = verification_engine.create_verification_challenge(
        wallet.address
    )

    verification_engine.challenge_engine.challenges[
        challenge["challenge_id"]
    ]["expires_at"] = 0

    result = verification_engine.verify_wallet(
        challenge["challenge_id"],
        wallet.address,
        "invalid_signature"
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_OR_EXPIRED_CHALLENGE"


# 7. Nonce Reuse Protection Test
def test_nonce_reuse_protection(wallet):

    nonce_engine = VOINNonceEngine()

    generated = nonce_engine.generate_nonce(
        wallet.address
    )

    first_check = nonce_engine.verify_nonce(
        wallet.address,
        generated["nonce"]
    )

    second_check = nonce_engine.verify_nonce(
        wallet.address,
        generated["nonce"]
    )

    assert first_check is True
    assert second_check is False


# 8. Engine Information Test
def test_verification_engine_info():

    info = VOINVerificationEngine.engine_info()

    assert info["engine"] == "VOIN Verification Engine"
    assert info["version"] == "1.0.0"
    assert info["status"] == "READY_FOR_TESTING"
