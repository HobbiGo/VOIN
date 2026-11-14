"""
VOIN DIGITAL SIGNATURE ENGINE V1.2

EVM-compatible digital signature verification.
Supports bytes, HexBytes and hexadecimal signatures.
"""

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import is_address, to_checksum_address


class VOINSignatureEngine:

    VERSION = "1.2.0"

    @staticmethod
    def validate_address(address):

        if not isinstance(address, str):
            return False

        return is_address(address)

    @staticmethod
    def normalize_signature(signature):

        if isinstance(signature, (bytes, bytearray)):
            signature = bytes(signature)

        elif isinstance(signature, str):

            signature = signature.strip()

            if signature.startswith("0x"):
                signature = signature[2:]

            try:
                signature = bytes.fromhex(signature)

            except ValueError:
                raise ValueError("Invalid signature format")

        else:
            raise ValueError("Invalid signature type")

        if len(signature) != 65:
            raise ValueError("Invalid signature length")

        return signature

    @classmethod
    def recover_signer(cls, message, signature):

        if not isinstance(message, str):
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
                expected_address
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
            "algorithm": "EIP-191",
            "signature_formats": [
                "BYTES",
                "HEXBYTES",
                "HEX_STRING"
            ],
            "network_support": [
                "BSC",
                "BSC_TESTNET",
                "EVM_COMPATIBLE"
            ],
            "status": "READY_FOR_TESTING"
        }
