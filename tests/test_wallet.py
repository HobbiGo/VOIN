"""
VOIN WALLET ENGINE TEST SUITE V1.0.2
SECURITY ENHANCEMENT

Tests:
- Engine initialization
- Wallet generation and uniqueness
- Address validation and checksum
- Private key validation
- Wallet information
- Private key encryption/decryption
- Password boundary validation
- Keystore size limitation
- Keystore structure validation
- Scrypt parameter validation
- PBKDF2 parameter validation
- Ciphertext validation
- Address mismatch detection
- Error message leakage protection
- Regression testing
"""

import copy
import json
import pytest

from eth_account import Account

from security.wallet import VOINWalletEngine


TEST_PASSWORD = "VOIN-Test-Password-2026!"


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
        TEST_PASSWORD
    )


@pytest.fixture
def parsed_keystore(keystore_data):
    return json.loads(keystore_data["keystore"])


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
    assert wallet["wallet_type"] == "ETHEREUM"
    assert wallet["version"] == "1.0.2"


def test_generated_wallet_address_is_valid(wallet):
    assert VOINWalletEngine.validate_address(wallet["address"])


def test_generated_wallet_private_key_is_valid(wallet):
    assert VOINWalletEngine.validate_private_key(
        wallet["private_key"]
    )


def test_generated_wallet_address_matches_private_key(wallet):
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
    assert VOINWalletEngine.validate_address(wallet["address"])


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
        "0x" + "z" * 40,
        "0x" + "1" * 39,
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
        VOINWalletEngine.get_address_checksum("invalid-address")


def test_checksum_address_from_lowercase(wallet):
    lowercase = wallet["address"].lower()

    checksum = VOINWalletEngine.get_address_checksum(lowercase)

    assert VOINWalletEngine.validate_address(checksum)


def test_invalid_mixed_case_checksum():
    # Known valid address with deliberately invalid capitalization.
    address = "0x52908400098527886E0F7030069857D2E4169Ee8"

    assert not VOINWalletEngine.validate_address(address)


def test_get_checksum_rejects_non_string():
    with pytest.raises(ValueError):
        VOINWalletEngine.get_address_checksum(None)


# --------------------------------------------------
# PRIVATE KEY VALIDATION
# --------------------------------------------------

def test_valid_private_key(wallet):
    assert VOINWalletEngine.validate_private_key(
        wallet["private_key"]
    )


def test_valid_private_key_without_prefix(wallet):
    private_key = wallet["private_key"].removeprefix("0x")

    assert VOINWalletEngine.validate_private_key(private_key)


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
        "g" * 64,
        "0x" + "1" * 63,
        "0x" + "1" * 65,
        "０" * 64,
    ]
)
def test_invalid_private_key(private_key):
    assert not VOINWalletEngine.validate_private_key(private_key)


def test_private_key_boundary_valid():
    # secp256k1 private key value 1 is valid.
    private_key = "0" * 63 + "1"

    assert VOINWalletEngine.validate_private_key(private_key)


def test_private_key_boundary_invalid():
    # secp256k1 curve order is not a valid private key.
    curve_order = (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
        "BAAEDCE6AF48A03BBFD25E8CD0364141"
    )

    assert not VOINWalletEngine.validate_private_key(curve_order)


# --------------------------------------------------
# WALLET INFORMATION
# --------------------------------------------------

def test_wallet_information(wallet):
    info = VOINWalletEngine.get_wallet_info(wallet["address"])

    assert info["address"] == wallet["address"]
    assert info["wallet_type"] == "ETHEREUM"
    assert info["address_valid"] is True
    assert info["checksum_valid"] is True
    assert info["private_key_exposed"] is False


def test_wallet_information_does_not_expose_private_key(wallet):
    info = VOINWalletEngine.get_wallet_info(wallet["address"])

    assert "private_key" not in info
    assert wallet["private_key"] not in json.dumps(info)


def test_wallet_information_invalid_address():
    with pytest.raises(ValueError):
        VOINWalletEngine.get_wallet_info("invalid-address")


# --------------------------------------------------
# PASSWORD VALIDATION
# --------------------------------------------------

def test_password_minimum_length():
    password = "A" * VOINWalletEngine.MIN_PASSWORD_LENGTH

    assert VOINWalletEngine._validate_password(password)


def test_password_maximum_length():
    password = "A" * VOINWalletEngine.MAX_PASSWORD_LENGTH

    assert VOINWalletEngine._validate_password(password)


@pytest.mark.parametrize(
    "password",
    [
        "",
        "short",
        "A" * (VOINWalletEngine.MIN_PASSWORD_LENGTH - 1),
        "A" * (VOINWalletEngine.MAX_PASSWORD_LENGTH + 1),
        None,
        123456789012,
        [],
        {},
    ]
)
def test_invalid_password(password):
    with pytest.raises(ValueError):
        VOINWalletEngine._validate_password(password)


def test_unicode_password():
    password = "VOIN-Secure-密码-2026!"

    assert VOINWalletEngine._validate_password(password)


def test_unicode_password_encryption(wallet):
    password = "VOIN-Secure-密码-2026!"

    encrypted = VOINWalletEngine.encrypt_private_key(
        wallet["private_key"],
        password
    )

    decrypted = VOINWalletEngine.decrypt_private_key(
        encrypted["keystore"],
        password
    )

    assert decrypted == wallet["private_key"]


# --------------------------------------------------
# HEX VALIDATION
# --------------------------------------------------

@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        12345,
        "xyz",
        "abc",
        "１２３４",
    ]
)
def test_invalid_hex(value):
    assert not VOINWalletEngine._valid_hex(value)


def test_valid_hex():
    assert VOINWalletEngine._valid_hex("aabbcc")


def test_valid_hex_expected_bytes():
    assert VOINWalletEngine._valid_hex(
        "a" * 32,
        expected_bytes=16
    )


def test_invalid_hex_expected_bytes():
    assert not VOINWalletEngine._valid_hex(
        "a" * 30,
        expected_bytes=16
    )


# --------------------------------------------------
# KEYSTORE VALIDATION
# --------------------------------------------------

def test_keystore_validation(parsed_keystore):
    assert VOINWalletEngine._validate_keystore(parsed_keystore)


def test_keystore_wrong_version(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    data["version"] = 2

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_keystore_invalid_crypto(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    data["crypto"] = None

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_keystore_invalid_cipher(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))
    crypto["cipher"] = "invalid-cipher"

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_keystore_invalid_iv(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))
    crypto["cipherparams"]["iv"] = "invalid"

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_keystore_invalid_mac(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))
    crypto["mac"] = "invalid"

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_keystore_empty_ciphertext(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))
    crypto["ciphertext"] = ""

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_keystore_invalid_kdf(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))
    crypto["kdf"] = "invalid"

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_keystore_invalid_dklen(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))
    crypto["kdfparams"]["dklen"] = 16

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_keystore_invalid_salt(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))
    crypto["kdfparams"]["salt"] = "invalid"

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_keystore_invalid_address(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    data["address"] = "invalid"

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


# --------------------------------------------------
# SCRYPT VALIDATION
# --------------------------------------------------

def test_scrypt_invalid_n(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))

    if crypto["kdf"] != "scrypt":
        pytest.skip("Keystore does not use scrypt")

    crypto["kdfparams"]["n"] = 3

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_scrypt_n_too_small(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))

    if crypto["kdf"] != "scrypt":
        pytest.skip("Keystore does not use scrypt")

    crypto["kdfparams"]["n"] = 2**11

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_scrypt_n_too_large(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))

    if crypto["kdf"] != "scrypt":
        pytest.skip("Keystore does not use scrypt")

    crypto["kdfparams"]["n"] = 2**21

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_scrypt_boolean_parameter_rejected(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))

    if crypto["kdf"] != "scrypt":
        pytest.skip("Keystore does not use scrypt")

    crypto["kdfparams"]["r"] = True

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


# --------------------------------------------------
# PBKDF2 VALIDATION
# --------------------------------------------------

def test_pbkdf2_invalid_iterations(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))

    crypto["kdf"] = "pbkdf2"
    crypto["kdfparams"]["c"] = 9999
    crypto["kdfparams"]["prf"] = "hmac-sha256"

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_pbkdf2_iterations_too_large(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))

    crypto["kdf"] = "pbkdf2"
    crypto["kdfparams"]["c"] = 2000001
    crypto["kdfparams"]["prf"] = "hmac-sha256"

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


def test_pbkdf2_invalid_prf(parsed_keystore):
    data = copy.deepcopy(parsed_keystore)
    crypto = data.get("crypto", data.get("Crypto"))

    crypto["kdf"] = "pbkdf2"
    crypto["kdfparams"]["c"] = 100000
    crypto["kdfparams"]["prf"] = "invalid"

    with pytest.raises(ValueError):
        VOINWalletEngine._validate_keystore(data)


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
    parsed = json.loads(keystore_data["keystore"])

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
            TEST_PASSWORD
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


def test_multiple_encryption_produces_different_keystores(wallet):
    first = VOINWalletEngine.encrypt_private_key(
        wallet["private_key"],
        TEST_PASSWORD
    )

    second = VOINWalletEngine.encrypt_private_key(
        wallet["private_key"],
        TEST_PASSWORD
    )

    assert first["keystore"] != second["keystore"]


# --------------------------------------------------
# PRIVATE KEY DECRYPTION
# --------------------------------------------------

def test_decrypt_private_key(wallet, keystore_data):
    decrypted = VOINWalletEngine.decrypt_private_key(
        keystore_data["keystore"],
        TEST_PASSWORD
    )

    assert decrypted == wallet["private_key"]


def test_decrypt_keystore_dictionary(wallet, keystore_data):
    decrypted = VOINWalletEngine.decrypt_private_key(
        json.loads(keystore_data["keystore"]),
        TEST_PASSWORD
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
            TEST_PASSWORD
        )


def test_decrypt_invalid_keystore_type():
    with pytest.raises(ValueError):
        VOINWalletEngine.decrypt_private_key(
            None,
            TEST_PASSWORD
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
            TEST_PASSWORD
        )


# --------------------------------------------------
# KEYSTORE SIZE LIMIT
# --------------------------------------------------

def test_keystore_string_size_limit():
    oversized = "A" * (
        VOINWalletEngine.MAX_KEYSTORE_SIZE + 1
    )

    with pytest.raises(ValueError):
        VOINWalletEngine.decrypt_private_key(
            oversized,
            TEST_PASSWORD
        )


def test_keystore_dictionary_size_limit():
    oversized = {
        "version": 3,
        "data": "A" * VOINWalletEngine.MAX_KEYSTORE_SIZE
    }

    with pytest.raises(ValueError):
        VOINWalletEngine.decrypt_private_key(
            oversized,
            TEST_PASSWORD
        )


# --------------------------------------------------
# ERROR MESSAGE LEAKAGE PROTECTION
# --------------------------------------------------

def test_wrong_password_error_does_not_leak_password(
    keystore_data
):
    password = "Sensitive-Test-Password-2026!"

    with pytest.raises(ValueError) as error:
        VOINWalletEngine.decrypt_private_key(
            keystore_data["keystore"],
            password
        )

    assert password not in str(error.value)


def test_invalid_keystore_error_is_generic():
    with pytest.raises(ValueError) as error:
        VOINWalletEngine.decrypt_private_key(
            "invalid-keystore",
            TEST_PASSWORD
        )

    assert str(error.value) == "Keystore decryption failed"


def test_error_does_not_leak_private_key(wallet):
    with pytest.raises(ValueError) as error:
        VOINWalletEngine.encrypt_private_key(
            "invalid-private-key",
            TEST_PASSWORD
        )

    assert wallet["private_key"] not in str(error.value)


# --------------------------------------------------
# SECURITY CONSISTENCY
# --------------------------------------------------

def test_encryption_decryption_preserves_wallet_address(
    wallet,
    keystore_data
):
    decrypted = VOINWalletEngine.decrypt_private_key(
        keystore_data["keystore"],
        TEST_PASSWORD
    )

    recovered_account = Account.from_key(decrypted)

    assert recovered_account.address == wallet["address"]


def test_multiple_encryption_operations(wallet):
    first = VOINWalletEngine.encrypt_private_key(
        wallet["private_key"],
        TEST_PASSWORD
    )

    second = VOINWalletEngine.encrypt_private_key(
        wallet["private_key"],
        TEST_PASSWORD
    )

    first_key = VOINWalletEngine.decrypt_private_key(
        first["keystore"],
        TEST_PASSWORD
    )

    second_key = VOINWalletEngine.decrypt_private_key(
        second["keystore"],
        TEST_PASSWORD
    )

    assert first_key == wallet["private_key"]
    assert second_key == wallet["private_key"]


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
