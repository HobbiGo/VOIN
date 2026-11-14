"""
VOIN AUTHENTICATION INTEGRATION TEST V1.0
"""

from eth_account import Account
from eth_account.messages import encode_defunct

from security.authentication import VOINAuthenticationEngine


def create_signed_authentication(engine, account):

    challenge = engine.create_authentication_challenge(
        account.address
    )

    assert challenge["success"] is True

    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=account.key
    )

    return engine.authenticate_wallet(
        challenge_id=challenge["challenge_id"],
        wallet_address=account.address,
        signature=signed.signature.hex()
    )


def test_authentication_success():

    engine = VOINAuthenticationEngine()

    account = Account.create()

    result = create_signed_authentication(
        engine,
        account
    )

    assert result["success"] is True
    assert result["status"] == "AUTHENTICATION_VERIFIED"


def test_authentication_replay_protection():

    engine = VOINAuthenticationEngine()

    account = Account.create()

    challenge = engine.create_authentication_challenge(
        account.address
    )

    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=account.key
    )

    first = engine.authenticate_wallet(
        challenge["challenge_id"],
        account.address,
        signed.signature.hex()
    )

    second = engine.authenticate_wallet(
        challenge["challenge_id"],
        account.address,
        signed.signature.hex()
    )

    assert first["success"] is True
    assert second["success"] is False


def test_authentication_invalid_signature():

    engine = VOINAuthenticationEngine()

    account = Account.create()

    challenge = engine.create_authentication_challenge(
        account.address
    )

    result = engine.authenticate_wallet(
        challenge["challenge_id"],
        account.address,
        "0x" + "00" * 65
    )

    assert result["success"] is False


def test_authentication_wrong_signer():

    engine = VOINAuthenticationEngine()

    account = Account.create()
    attacker = Account.create()

    challenge = engine.create_authentication_challenge(
        account.address
    )

    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]),
        private_key=attacker.key
    )

    result = engine.authenticate_wallet(
        challenge["challenge_id"],
        account.address,
        signed.signature.hex()
    )

    assert result["success"] is False
    assert result["status"] == "SIGNER_MISMATCH"


def test_authentication_invalid_wallet():

    engine = VOINAuthenticationEngine()

    result = engine.create_authentication_challenge(
        "INVALID_WALLET"
    )

    assert result["success"] is False
    assert result["status"] == "INVALID_ADDRESS"
