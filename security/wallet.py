"""
VOIN WALLET ENGINE V1.0.1

Secure wallet generation, address validation,
private key validation and encrypted keystore management.

Security:
- Cryptographically secure wallet generation
- Ethereum-compatible addresses
- EIP-55 checksum validation
- Encrypted Ethereum V3 keystore
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


class VOINWalletEngine:

    VERSION = "1.0.1"

    ENGINE_NAME = "VOIN Wallet Engine"

    KEYSTORE_VERSION = 3

    def __init__(self):

        self.status = "READY"

    # --------------------------------------------------
    # WALLET GENERATION
    # --------------------------------------------------

    @staticmethod
    def generate_wallet():

        account = Account.create()

        return {
            "address": account.address,
            "private_key": account.key.hex(),
            "wallet_type": "ETHEREUM",
            "version": VOINWalletEngine.VERSION,
        }

    # --------------------------------------------------
    # ADDRESS VALIDATION
    # --------------------------------------------------

    @staticmethod
    def validate_address(address):

        if not isinstance(address, str):
            return False

        address = address.strip()

        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
            return False

        body = address[2:]

        # Uniform lowercase or uppercase hexadecimal
        # addresses are valid Ethereum address formats.
        if body == body.lower() or body == body.upper():
            return True

        # Mixed-case addresses must pass EIP-55 checksum.
        return is_checksum_address(address)

    # --------------------------------------------------
    # CHECKSUM ADDRESS
    # --------------------------------------------------

    @staticmethod
    def get_address_checksum(address):

        if not isinstance(address, str):
            raise ValueError("Invalid wallet address")

        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
            raise ValueError("Invalid wallet address")

        return to_checksum_address(address)

    # --------------------------------------------------
    # PRIVATE KEY VALIDATION
    # --------------------------------------------------

    @staticmethod
    def validate_private_key(private_key):

        if not isinstance(private_key, str):
            return False

        key = private_key.strip()

        if key.startswith("0x"):
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
    def get_wallet_info(address):

        if not VOINWalletEngine.validate_address(address):
            raise ValueError("Invalid wallet address")

        checksum_address = to_checksum_address(address)

        return {
            "address": checksum_address,
            "wallet_type": "ETHEREUM",
            "address_valid": True,
            "checksum_valid": True,
            "private_key_exposed": False,
        }

    # --------------------------------------------------
    # PRIVATE KEY ENCRYPTION
    # --------------------------------------------------

    @staticmethod
    def encrypt_private_key(private_key, password):

        if not VOINWalletEngine.validate_private_key(private_key):
            raise ValueError("Invalid private key")

        if not isinstance(password, str) or len(password) < 12:
            raise ValueError(
                "Password must contain at least 12 characters"
            )

        account = Account.from_key(private_key)

        encrypted = Account.encrypt(
            account.key,
            password
        )

        # eth-account may return a dictionary,
        # bytes, or JSON string depending on version.

        if isinstance(encrypted, bytes):

            encrypted = encrypted.decode("utf-8")

        if isinstance(encrypted, str):

            keystore_data = json.loads(encrypted)

        elif isinstance(encrypted, dict):

            keystore_data = encrypted

        else:

            raise ValueError("Unsupported keystore format")

        if keystore_data.get("version") != 3:
            raise ValueError("Unsupported keystore version")

        keystore_json = json.dumps(
            keystore_data,
            separators=(",", ":")
        )

        return {
            "address": account.address,
            "keystore": keystore_json,
            "keystore_version": 3,
            "encrypted": True,
        }

    # --------------------------------------------------
    # PRIVATE KEY DECRYPTION
    # --------------------------------------------------

    @staticmethod
    def decrypt_private_key(keystore, password):

        if not isinstance(keystore, (str, dict)):
            raise ValueError("Invalid keystore")

        if not isinstance(password, str) or not password:
            raise ValueError("Invalid password")

        try:

            if isinstance(keystore, str):

                keystore_data = json.loads(keystore)

            else:

                keystore_data = keystore

            if not isinstance(keystore_data, dict):
                raise ValueError("Invalid keystore format")

            if keystore_data.get("version") != 3:
                raise ValueError("Unsupported keystore version")

            private_key = Account.decrypt(
                keystore_data,
                password
            )

            return private_key.hex()

        except ValueError:

            raise

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
            "wallet_type": "ETHEREUM",
            "address_standard": "EIP-55",
            "keystore_standard": "Ethereum V3",
            "secure_random_generation": True,
            "private_key_encryption": True,
            "private_key_logging": False,
            "automatic_private_key_storage": False,
            "recovery_backdoor": False,
            "status": "READY_FOR_TESTING",
        }
