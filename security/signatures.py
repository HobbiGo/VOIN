"""
VOIN DIGITAL SIGNATURE ENGINE V1.0

Provides EVM-compatible digital signature
verification for VOIN.
"""

from eth_account import Account
from eth_account.messages import encode_defunct


class VOINSignatureEngine:

    VERSION = "1.0.0"

    @staticmethod
    def validate_address(address):

        if not isinstance(address, str):
            return False

        return Account.is_address(address)

    @staticmethod
    def recover_signer(message, signature):

        if not isinstance(message, str):
            raise ValueError("Invalid message")

        if not isinstance(signature, str):
            raise ValueError("Invalid signature")

        encoded_message = encode_defunct(
            text=message
        )

        try:
            signer = Account.recover_message(
                encoded_message,
                signature=signature
            )

            return Account.to_checksum_address(signer)

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

            expected = Account.to_checksum_address(
                expected_address
            )

            if recovered != expected:
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
            "network_support": [
                "BSC",
                "BSC_TESTNET",
                "EVM_COMPATIBLE"
            ],
            "status": "READY_FOR_TESTING"
        }
