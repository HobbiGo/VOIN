"""
VOIN WALLET ENGINE TEST SUITE V1.0.2

Tests:
- Engine initialization
- Wallet generation
- Wallet uniqueness
- Address validation
- Address checksum
- Private key validation
- Wallet information
- Private key encryption
- Private key decryption
- Invalid password handling
- Invalid keystore handling
- Invalid input handling
- Engine information
"""

import json
import pytest

from security.wallet import VOINWalletEngine


# --------------------------------------------------
# FIXTURES
# --------------------------------------------------

@pytest.fixture
def engine():
    return VOINWalletEngine()


@pytest.fixture
def wallet():
    return VOINWalletEngine.generate_wallet()


@pytest.fixture
def keystore_data(wallet):
    return VOINWalletEngine.encrypt_private_key(
        wallet["private_key"],
        "VOIN-Test-Password-2026!"
    )


# --------------------------------------------------
# ENGINE INITIALIZATION
# --------------------------------------------------

def test_engine_initialization(engine):

    assert engine is not None
    assert engine.status == "READY"


def test_engine_version():

    assert VOINWalletEngine.VERSION == "1.0.2"


# --------------------------------------------------
# WALLET GENERATION
# --------------------------------------------------

def test_generate_wallet(wallet):

    assert isinstance(wallet, dict)

    assert "address" in wallet
    assert "private_key" in wallet
    assert "wallet_type" in wallet
    assert "version" in wallet

    assert wallet["wallet_type"] == "ETHEREUM"
    assert wallet["version"] == "1.0.2"


def test_generated_wallet_address_is_valid(wallet):

    assert VOINWalletEngine.validate_address(
        wallet["address"]
    )


def test_generated_wallet_private_key_is_valid(wallet):

    assert VOINWalletEngine.validate_private_key(
        wallet["private_key"]
    )


def test_generated_wallet_address_matches_private_key(wallet):

    from eth_account import Account

    account = Account.from_key(wallet["private_key"])

    assert account.address == wallet["address"]


def test_wallet_generation_uniqueness():

    wallet_a = VOINWalletEngine.generate_wallet()
    wallet_b = VOINWalletEngine.generate_wallet()

    assert wallet_a["address"] != wallet_b["address"]

    assert wallet_a["private_key"] != wallet_b["private_key"]


# --------------------------------------------------
# ADDRESS VALIDATION
# --------------------------------------------------

def test_valid_address(wallet):

    assert VOINWalletEngine.validate_address(
        wallet["address"]
    )


@pytest.mark.parametrize(
    "address",
    [
        "",
        "invalid",
        "0x123",
        None,
        12345,
        [],
        {},
    ]
)
def test_invalid_address(address):

    assert not VOINWalletEngine.validate_address(address)


def test_checksum_address(wallet):

    checksum = VOINWalletEngine.get_address_checksum(
        wallet["address"]
    )

    assert checksum == wallet["address"]


def test_checksum_address_invalid_input():

    with pytest.raises(ValueError):

        VOINWalletEngine.get_address_checksum(
            "invalid-address"
        )


def test_checksum_address_from_lowercase(wallet):

    lowercase = wallet["address"].lower()

    checksum = VOINWalletEngine.get_address_checksum(
        lowercase
    )

    assert VOINWalletEngine.validate_address(checksum)


def test_invalid_mixed_case_checksum():

    address = "0x52908400098527886E0F7030069857D2E4169EE8"

    assert VOINWalletEngine.validate_address(address)


# --------------------------------------------------
# PRIVATE KEY VALIDATION
# --------------------------------------------------

def test_valid_private_key(wallet):

    assert VOINWalletEngine.validate_private_key(
        wallet["private_key"]
    )


def test_valid_private_key_without_prefix(wallet):

    private_key = wallet["private_key"].removeprefix("0x")

    assert VOINWalletEngine.validate_private_key(
        private_key
    )


@pytest.mark.parametrize(
    "private_key",
    [
        "",
        "invalid",
        "0x1234",
        "0" * 64,
        None,
        12345,
        [],
        {},
    ]
)
def test_invalid_private_key(private_key):

    assert not VOINWalletEngine.validate_private_key(
        private_key
    )


# --------------------------------------------------
# WALLET INFORMATION
# --------------------------------------------------

def test_wallet_information(wallet):

    info = VOINWalletEngine.get_wallet_info(
        wallet["address"]
    )

    assert info["address"] == wallet["address"]

    assert info["wallet_type"] == "ETHEREUM"

    assert info["address_valid"] is True

    assert info["checksum_valid"] is True

    assert info["private_key_exposed"] is False


def test_wallet_information_does_not_expose_private_key(wallet):

    info = VOINWalletEngine.get_wallet_info(
        wallet["address"]
    )

    assert "private_key" not in info

    assert wallet["private_key"] not in json.dumps(info)


def test_wallet_information_invalid_address():

    with pytest.raises(ValueError):

        VOINWalletEngine.get_wallet_info(
            "invalid-address"
        )


# --------------------------------------------------
# PRIVATE KEY ENCRYPTION
# --------------------------------------------------

def test_encrypt_private_key(wallet, keystore_data):

    assert isinstance(keystore_data, dict)

    assert keystore_data["encrypted"] is True

    assert keystore_data["keystore_version"] == 3

    assert keystore_data["address"] == wallet["address"]

    assert "keystore" in keystore_data


def test_keystore_is_valid_json(keystore_data):

    parsed = json.loads(
        keystore_data["keystore"]
    )

    assert parsed["version"] == 3

    assert "crypto" in parsed or "Crypto" in parsed


def test_keystore_does_not_contain_plaintext_private_key(
    wallet,
    keystore_data
):

    assert wallet["private_key"].lower() not in (
        keystore_data["keystore"].lower()
    )


def test_encrypt_invalid_private_key():

    with pytest.raises(ValueError):

        VOINWalletEngine.encrypt_private_key(
            "invalid-private-key",
            "VOIN-Test-Password-2026!"
        )


def test_encrypt_short_password(wallet):

    with pytest.raises(ValueError):

        VOINWalletEngine.encrypt_private_key(
            wallet["private_key"],
            "short"
        )


def test_encrypt_invalid_password_type(wallet):

    with pytest.raises(ValueError):

        VOINWalletEngine.encrypt_private_key(
            wallet["private_key"],
            None
        )


# --------------------------------------------------
# PRIVATE KEY DECRYPTION
# --------------------------------------------------

def test_decrypt_private_key(wallet, keystore_data):

    decrypted = VOINWalletEngine.decrypt_private_key(
        keystore_data["keystore"],
        "VOIN-Test-Password-2026!"
    )

    assert decrypted == wallet["private_key"]


def test_decrypt_keystore_dictionary(wallet, keystore_data):

    decrypted = VOINWalletEngine.decrypt_private_key(
        json.loads(keystore_data["keystore"]),
        "VOIN-Test-Password-2026!"
    )

    assert decrypted == wallet["private_key"]


def test_decrypt_wrong_password(keystore_data):

    with pytest.raises(ValueError):

        VOINWalletEngine.decrypt_private_key(
            keystore_data["keystore"],
            "Wrong-Password-2026!"
        )


def test_decrypt_invalid_keystore():

    with pytest.raises(ValueError):

        VOINWalletEngine.decrypt_private_key(
            "invalid-keystore",
            "VOIN-Test-Password-2026!"
        )


def test_decrypt_invalid_keystore_type():

    with pytest.raises(ValueError):

        VOINWalletEngine.decrypt_private_key(
            None,
            "VOIN-Test-Password-2026!"
        )


def test_decrypt_empty_password(keystore_data):

    with pytest.raises(ValueError):

        VOINWalletEngine.decrypt_private_key(
            keystore_data["keystore"],
            ""
        )


def test_decrypt_unsupported_keystore_version():

    keystore = {
        "version": 2,
        "crypto": {}
    }

    with pytest.raises(ValueError):

        VOINWalletEngine.decrypt_private_key(
            keystore,
            "VOIN-Test-Password-2026!"
        )


# --------------------------------------------------
# ENGINE INFORMATION
# --------------------------------------------------

def test_engine_info():

    info = VOINWalletEngine.engine_info()

    assert info["engine"] == "VOIN Wallet Engine"

    assert info["version"] == "1.0.2"

    assert info["wallet_type"] == "ETHEREUM"

    assert info["address_standard"] == "EIP-55"

    assert info["keystore_standard"] == "Ethereum V3"

    assert info["secure_random_generation"] is True

    assert info["private_key_encryption"] is True

    assert info["private_key_logging"] is False

    assert info["automatic_private_key_storage"] is False

    assert info["recovery_backdoor"] is False

    assert info["status"] == "READY_FOR_TESTING"


# --------------------------------------------------
# SECURITY CONSISTENCY
# --------------------------------------------------

def test_encryption_decryption_preserves_wallet_address(
    wallet,
    keystore_data
):

    decrypted = VOINWalletEngine.decrypt_private_key(
        keystore_data["keystore"],
        "VOIN-Test-Password-2026!"
    )

    from eth_account import Account

    recovered_account = Account.from_key(decrypted)

    assert recovered_account.address == wallet["address"]


def test_multiple_encryption_operations(wallet):

    password = "VOIN-Test-Password-2026!"

    first = VOINWalletEngine.encrypt_private_key(
        wallet["private_key"],
        password
    )

    second = VOINWalletEngine.encrypt_private_key(
        wallet["private_key"],
        password
    )

    first_key = VOINWalletEngine.decrypt_private_key(
        first["keystore"],
        password
    )

    second_key = VOINWalletEngine.decrypt_private_key(
        second["keystore"],
        password
    )

    assert first_key == wallet["private_key"]

    assert second_key == wallet["private_key"]
