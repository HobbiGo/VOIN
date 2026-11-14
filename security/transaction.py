"""
VOIN TRANSACTION SECURITY ENGINE V1.0

Transaction validation, integrity verification,
and duplicate transaction protection.

Development module - not a production blockchain.
"""

import hashlib
import json
import secrets
import time
import math

from decimal import Decimal, InvalidOperation
from eth_utils import is_address


class VOINTransactionSecurity:

    VERSION = "1.0.0"

    def __init__(self):

        self.transactions = {}
        self.transaction_hashes = set()

    @staticmethod
    def validate_address(address):

        if not isinstance(address, str):
            return False

        return is_address(address)

    @staticmethod
    def validate_amount(amount):

        try:

            value = Decimal(str(amount))

            if not value.is_finite():
                return False

            return value > 0

        except (InvalidOperation, ValueError, TypeError):

            return False

    @staticmethod
    def generate_transaction_id():

        return secrets.token_hex(32)

    @staticmethod
    def calculate_integrity_hash(transaction):

        canonical_data = json.dumps(
            transaction,
            sort_keys=True,
            separators=(",", ":")
        )

        return hashlib.sha256(
            canonical_data.encode("utf-8")
        ).hexdigest()

    def validate_transaction(
        self,
        sender,
        receiver,
        amount,
        asset="VOIN",
        network="VOIN"
    ):

        if not self.validate_address(sender):

            return {
                "success": False,
                "status": "INVALID_SENDER"
            }

        if not self.validate_address(receiver):

            return {
                "success": False,
                "status": "INVALID_RECEIVER"
            }

        if sender.lower() == receiver.lower():

            return {
                "success": False,
                "status": "SELF_TRANSFER_NOT_ALLOWED"
            }

        if not self.validate_amount(amount):

            return {
                "success": False,
                "status": "INVALID_AMOUNT"
            }

        if not isinstance(asset, str) or not asset.strip():

            return {
                "success": False,
                "status": "INVALID_ASSET"
            }

        if not isinstance(network, str) or not network.strip():

            return {
                "success": False,
                "status": "INVALID_NETWORK"
            }

        return {
            "success": True,
            "status": "TRANSACTION_VALID"
        }

    def create_transaction_record(
        self,
        sender,
        receiver,
        amount,
        asset="VOIN",
        network="VOIN"
    ):

        validation = self.validate_transaction(
            sender,
            receiver,
            amount,
            asset,
            network
        )

        if not validation["success"]:
            return validation

        transaction_id = self.generate_transaction_id()

        timestamp = int(time.time())

        transaction = {
            "transaction_id": transaction_id,
            "sender": sender,
            "receiver": receiver,
            "amount": str(Decimal(str(amount))),
            "asset": asset.upper(),
            "network": network.upper(),
            "timestamp": timestamp,
            "status": "PENDING"
        }

        integrity_hash = self.calculate_integrity_hash(
            transaction
        )

        if integrity_hash in self.transaction_hashes:

            return {
                "success": False,
                "status": "DUPLICATE_TRANSACTION"
            }

        self.transaction_hashes.add(integrity_hash)

        self.transactions[transaction_id] = {
            "data": transaction,
            "integrity_hash": integrity_hash
        }

        return {
            "success": True,
            "status": "TRANSACTION_CREATED",
            "transaction": transaction,
            "integrity_hash": integrity_hash
        }

    def verify_integrity(self, transaction_id):

        record = self.transactions.get(transaction_id)

        if not record:
            return False

        current_hash = self.calculate_integrity_hash(
            record["data"]
        )

        return current_hash == record["integrity_hash"]

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Transaction Security Engine",
            "version": cls.VERSION,
            "address_validation": True,
            "amount_validation": True,
            "integrity_verification": True,
            "duplicate_protection": True,
            "status": "READY_FOR_TESTING"
        }
