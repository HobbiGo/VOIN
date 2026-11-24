"""
VOIN WALLET ENGINE V1.0.2

Secure wallet generation, address validation,
private key validation and encrypted keystore management.

Security:
- Cryptographically secure wallet generation
- Ethereum-compatible addresses (EVM / BSC Mainnet Chain ID 56)
- EIP-55 checksum validation
- Ethereum V3 keystore validation
- Bounded KDF parameters
- Encrypted private key management
- No plaintext private key persistence
- No private key or password logging
"""

import json
import re

from eth_account import Account
from eth_utils import (
    is_checksum_address,
    to_checksum_address,
)

ZERO_ADDRESS = "0x" + ("0" * 40)


class VOINWalletEngine:

    VERSION = "1.0.2"

    ENGINE_NAME = "VOIN Wallet Engine"

    KEYSTORE_VERSION = 3

    MAX_KEYSTORE_SIZE = 65536

    MIN_PASSWORD_LENGTH = 12

    MAX_PASSWORD_LENGTH = 1024

    # --------------------------------------------------
    # INITIALIZATION
    # --------------------------------------------------

    def __init__(self):

        self.status = "READY"

    # --------------------------------------------------
    # INTERNAL HELPERS
    # --------------------------------------------------

    @staticmethod
    def _format_hex_key(raw_key) -> str:
        if isinstance(raw_key, bytes):
            hex_str = raw_key.hex()
        else:
            hex_str = str(raw_key).strip()
        if hex_str.startswith(("0x", "0X")):
            hex_str = hex_str[2:]
        return "0x" + hex_str.lower()

    # --------------------------------------------------
    # WALLET GENERATION
    # --------------------------------------------------

    @staticmethod
    def generate_wallet():
        """
        Generate a new EVM-compatible wallet.

        IMPORTANT:
        The private key is returned in plaintext.
        The caller must protect it immediately.
        """

        account = Account.create()

        return {
            "address": to_checksum_address(account.address),
            "private_key": VOINWalletEngine._format_hex_key(account.key),
            "wallet_type": "EVM",
            "version": VOINWalletEngine.VERSION,
        }

    # --------------------------------------------------
    # ADDRESS VALIDATION
    # --------------------------------------------------

    @staticmethod
    def validate_address(address, *, allow_zero: bool = False):

        if not isinstance(address, str):
            return False

        cleaned = address.strip()

        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", cleaned):
            return False

        if not allow_zero and cleaned.lower() == ZERO_ADDRESS:
            return False

        body = cleaned[2:]

        if body == body.lower() or body == body.upper():
            return True

        return is_checksum_address(cleaned)

    # --------------------------------------------------
    # CHECKSUM ADDRESS
    # --------------------------------------------------

    @staticmethod
    def get_address_checksum(address, *, allow_zero: bool = False):

        if not VOINWalletEngine.validate_address(address, allow_zero=allow_zero):
            raise ValueError("Invalid wallet address")

        return to_checksum_address(address.strip())

    # --------------------------------------------------
    # PRIVATE KEY VALIDATION
    # --------------------------------------------------

    @staticmethod
    def validate_private_key(private_key):

        if not isinstance(private_key, str):
            return False

        key = private_key.strip()

        if key.startswith(("0x", "0X")):
            key = key[2:]

        if not re.fullmatch(r"[0-9a-fA-F]{64}", key):
            return False

        try:

            Account.from_key(key)

            return True

        except Exception:

            return False

    # --------------------------------------------------
    # WALLET INFORMATION
    # --------------------------------------------------

    @staticmethod
    def get_wallet_info(address, *, allow_zero: bool = False):

        if not VOINWalletEngine.validate_address(address, allow_zero=allow_zero):
            raise ValueError("Invalid wallet address")

        checksum_address = to_checksum_address(address.strip())

        return {
            "address": checksum_address,
            "normalized_address": checksum_address.lower(),
            "wallet_type": "EVM",
            "address_valid": True,
            "checksum_valid": True,
            "private_key_exposed": False,
        }

    # --------------------------------------------------
    # PASSWORD VALIDATION
    # --------------------------------------------------

    @staticmethod
    def _validate_password(password):

        if not isinstance(password, str):
            raise ValueError("Invalid password")

        if not (
            VOINWalletEngine.MIN_PASSWORD_LENGTH
            <= len(password)
            <= VOINWalletEngine.MAX_PASSWORD_LENGTH
        ):
            raise ValueError("Invalid password length")

        return True

    # --------------------------------------------------
    # HEX VALIDATION
    # --------------------------------------------------

    @staticmethod
    def _valid_hex(value, expected_bytes=None):

        if not isinstance(value, str):
            return False

        if not re.fullmatch(r"[0-9a-fA-F]+", value):
            return False

        if len(value) % 2 != 0:
            return False

        if expected_bytes is not None:
            return len(value) == expected_bytes * 2

        return True

    # --------------------------------------------------
    # KEYSTORE VALIDATION
    # --------------------------------------------------

    @staticmethod
    def _validate_keystore(keystore_data):

        if not isinstance(keystore_data, dict):
            raise ValueError("Invalid keystore")

        if keystore_data.get("version") != 3:
            raise ValueError("Invalid keystore")

        crypto = keystore_data.get("crypto")

        if crypto is None:
            crypto = keystore_data.get("Crypto")

        if not isinstance(crypto, dict):
            raise ValueError("Invalid keystore")

        # Cipher validation

        if crypto.get("cipher") != "aes-128-ctr":
            raise ValueError("Invalid keystore")

        cipherparams = crypto.get("cipherparams")

        if not isinstance(cipherparams, dict):
            raise ValueError("Invalid keystore")

        if not VOINWalletEngine._valid_hex(
            cipherparams.get("iv"),
            expected_bytes=16
        ):
            raise ValueError("Invalid keystore")

        # MAC validation

        if not VOINWalletEngine._valid_hex(
            crypto.get("mac"),
            expected_bytes=32
        ):
            raise ValueError("Invalid keystore")

        # Ciphertext validation

        ciphertext = crypto.get("ciphertext")

        if not VOINWalletEngine._valid_hex(ciphertext):
            raise ValueError("Invalid keystore")

        # KDF validation

        kdf = crypto.get("kdf")

        kdfparams = crypto.get("kdfparams")

        if not isinstance(kdfparams, dict):
            raise ValueError("Invalid keystore")

        if kdfparams.get("dklen") != 32:
            raise ValueError("Invalid keystore")

        salt = kdfparams.get("salt")

        if not VOINWalletEngine._valid_hex(salt):
            raise ValueError("Invalid keystore")

        if len(salt) < 32 or len(salt) > 128:
            raise ValueError("Invalid keystore")

        # Scrypt validation

        if kdf == "scrypt":

            n = kdfparams.get("n")
            r = kdfparams.get("r")
            p = kdfparams.get("p")

            if not all(
                isinstance(value, int) and not isinstance(value, bool)
                for value in (n, r, p)
            ):
                raise ValueError("Invalid keystore")

            if n < 2**12 or n > 2**20:
                raise ValueError("Invalid keystore")

            if n & (n - 1):
                raise ValueError("Invalid keystore")

            if r < 1 or r > 16:
                raise ValueError("Invalid keystore")

            if p < 1 or p > 4:
                raise ValueError("Invalid keystore")

            estimated_memory = 128 * n * r

            if estimated_memory > 512 * 1024 * 1024:
                raise ValueError("Invalid keystore")

            estimated_work = n * r * p

            if estimated_work > 8_388_608:
                raise ValueError("Invalid keystore")

        # PBKDF2 validation

        elif kdf == "pbkdf2":

            iterations = kdfparams.get("c")

            prf = kdfparams.get("prf")

            if (
                not isinstance(iterations, int)
                or isinstance(iterations, bool)
            ):
                raise ValueError("Invalid keystore")

            if iterations < 10000 or iterations > 2000000:
                raise ValueError("Invalid keystore")

            if prf != "hmac-sha256":
                raise ValueError("Invalid keystore")

        else:

            raise ValueError("Invalid keystore")

        # Optional address validation

        address = keystore_data.get("address")

        if address is not None:

            if not isinstance(address, str):
                raise ValueError("Invalid keystore")

            if not re.fullmatch(r"[0-9a-fA-F]{40}", address):
                raise ValueError("Invalid keystore")

        return True

    # --------------------------------------------------
    # PRIVATE KEY ENCRYPTION
    # --------------------------------------------------

    @staticmethod
    def encrypt_private_key(private_key, password):

        if not VOINWalletEngine.validate_private_key(private_key):
            raise ValueError("Invalid private key")

        VOINWalletEngine._validate_password(password)

        account = Account.from_key(private_key.strip())

        encrypted = Account.encrypt(
            account.key,
            password
        )

        if isinstance(encrypted, bytes):

            encrypted = encrypted.decode("utf-8")

        if isinstance(encrypted, str):

            keystore_data = json.loads(encrypted)

        elif isinstance(encrypted, dict):

            keystore_data = encrypted

        else:

            raise ValueError("Unsupported keystore format")

        VOINWalletEngine._validate_keystore(keystore_data)

        keystore_address = keystore_data.get("address")

        if keystore_address is not None:

            if keystore_address.lower() != account.address[2:].lower():
                raise ValueError("Keystore address mismatch")

        keystore_json = json.dumps(
            keystore_data,
            separators=(",", ":")
        )

        if len(keystore_json.encode("utf-8")) > (
            VOINWalletEngine.MAX_KEYSTORE_SIZE
        ):
            raise ValueError("Keystore too large")

        return {
            "address": to_checksum_address(account.address),
            "keystore": keystore_json,
            "keystore_version": VOINWalletEngine.KEYSTORE_VERSION,
            "encrypted": True,
        }

    # --------------------------------------------------
    # PRIVATE KEY DECRYPTION
    # --------------------------------------------------

    @staticmethod
    def decrypt_private_key(keystore, password):

        try:

            VOINWalletEngine._validate_password(password)

            if isinstance(keystore, str):

                if len(keystore.encode("utf-8")) > (
                    VOINWalletEngine.MAX_KEYSTORE_SIZE
                ):
                    raise ValueError("Invalid keystore")

                keystore_data = json.loads(keystore)

            elif isinstance(keystore, dict):

                keystore_data = keystore

                encoded_size = len(
                    json.dumps(keystore_data).encode("utf-8")
                )

                if encoded_size > VOINWalletEngine.MAX_KEYSTORE_SIZE:
                    raise ValueError("Invalid keystore")

            else:

                raise ValueError("Invalid keystore")

            VOINWalletEngine._validate_keystore(keystore_data)

            private_key = Account.decrypt(
                keystore_data,
                password
            )

            account = Account.from_key(private_key)

            stored_address = keystore_data.get("address")

            if stored_address is not None:

                if stored_address.lower() != account.address[2:].lower():
                    raise ValueError("Keystore address mismatch")

            return VOINWalletEngine._format_hex_key(private_key)

        except Exception:

            raise ValueError(
                "Keystore decryption failed"
            ) from None

    # --------------------------------------------------
    # WALLET ENGINE INFORMATION
    # --------------------------------------------------

    @classmethod
    def engine_info(cls):

        return {
            "engine": cls.ENGINE_NAME,
            "version": cls.VERSION,
            "wallet_type": "EVM",
            "address_standard": "EIP-55",
            "keystore_standard": "Ethereum V3",
            "secure_random_generation": True,
            "private_key_encryption": True,
            "private_key_logging": False,
            "automatic_private_key_storage": False,
            "recovery_backdoor": False,
            "status": "MAINNET_READY",
        }
