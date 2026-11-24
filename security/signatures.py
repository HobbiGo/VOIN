"""
VOIN DIGITAL SIGNATURE ENGINE V1.2

EVM-compatible digital signature verification (BSC Mainnet / Chain ID 56).
Supports bytes, HexBytes and hexadecimal signatures.
"""

import re

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import is_address, to_checksum_address

_EVM_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = "0x" + ("0" * 40)
DEFAULT_CHAIN_ID = 56


class VOINSignatureEngine:

    VERSION = "1.2.0"

    @staticmethod
    def validate_address(address, *, allow_zero: bool = False):

        if not isinstance(address, str):
            return False

        cleaned = address.strip()
        if not _EVM_HEX_RE.match(cleaned) or not is_address(cleaned):
            return False

        if not allow_zero and cleaned.lower() == _ZERO_ADDRESS:
            return False

        return True

    @classmethod
    def normalize_address(cls, address, *, allow_zero: bool = False) -> str:
        if not cls.validate_address(address, allow_zero=allow_zero):
            raise ValueError("Invalid EVM wallet address")
        return address.strip().lower()

    @staticmethod
    def normalize_signature(signature):

        if isinstance(signature, (bytes, bytearray)):
            raw_bytes = bytes(signature)

        elif hasattr(signature, "hex") and callable(signature.hex) and not isinstance(signature, str):
            hex_val = signature.hex()
            if isinstance(hex_val, str):
                hex_str = hex_val.strip()
                if hex_str.startswith(("0x", "0X")):
                    hex_str = hex_str[2:]
                try:
                    raw_bytes = bytes.fromhex(hex_str)
                except ValueError as exc:
                    raise ValueError("Invalid signature format") from exc
            else:
                raise ValueError("Invalid signature format")

        elif isinstance(signature, str):

            hex_str = signature.strip()

            if hex_str.startswith(("0x", "0X")):
                hex_str = hex_str[2:]

            try:
                raw_bytes = bytes.fromhex(hex_str)

            except ValueError as exc:
                raise ValueError("Invalid signature format") from exc

        else:
            raise ValueError("Invalid signature type")

        if len(raw_bytes) != 65:
            raise ValueError("Invalid signature length")

        return raw_bytes

    @classmethod
    def recover_signer(cls, message, signature):

        if not isinstance(message, str) or not message:
            raise ValueError("Invalid message")

        normalized_signature = cls.normalize_signature(
            signature
        )

        encoded_message = encode_defunct(
            text=message
        )

        try:

            signer = Account.recover_message(
                encoded_message,
                signature=normalized_signature
            )

            return to_checksum_address(signer)

        except Exception as error:

            raise ValueError(
                "Signature verification failed"
            ) from error

    @classmethod
    def verify_signature(
        cls,
        message,
        signature,
        expected_address
    ):

        if not cls.validate_address(expected_address):
            return {
                "success": False,
                "status": "INVALID_ADDRESS"
            }

        try:

            recovered = cls.recover_signer(
                message,
                signature
            )

            expected = to_checksum_address(
                expected_address.strip()
            )

            if recovered.lower() != expected.lower():

                return {
                    "success": False,
                    "status": "SIGNER_MISMATCH"
                }

            return {
                "success": True,
                "status": "SIGNATURE_VALID",
                "signer": recovered,
                "normalized_signer": recovered.lower(),
                "engine": "VOIN Signature Engine",
                "version": cls.VERSION
            }

        except ValueError:

            return {
                "success": False,
                "status": "INVALID_SIGNATURE"
            }

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Digital Signature Engine",
            "version": cls.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "algorithm": "EIP-191",
            "signature_formats": [
                "BYTES",
                "HEXBYTES",
                "HEX_STRING"
            ],
            "network_support": [
                "BSC_MAINNET",
                "BSC",
                "EVM_COMPATIBLE"
            ],
            "status": "MAINNET_READY"
        }
