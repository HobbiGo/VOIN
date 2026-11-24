"""
VOIN TRANSACTION SECURITY ENGINE V1.1

Transaction validation, integrity verification,
duplicate request protection and status management.

Target Environment: BSC Mainnet (Chain ID 56) / EVM
"""

import hashlib
import json
import re
import secrets
import time
import threading

from decimal import Decimal, InvalidOperation
from eth_utils import is_address

_EVM_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = "0x" + ("0" * 40)
DEFAULT_CHAIN_ID = 56


class VOINTransactionSecurity:

    VERSION = "1.1.0"

    VALID_STATUSES = {
        "PENDING",
        "VERIFIED",
        "REJECTED"
    }

    def __init__(self, chain_id=DEFAULT_CHAIN_ID):

        if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
            raise ValueError("Invalid chain_id")

        self.chain_id = chain_id
        self.transactions = {}
        self.idempotency_records = {}
        self.lock = threading.RLock()

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

    @staticmethod
    def _format_decimal(value: Decimal) -> str:
        text = format(value, "f")
        if "." in text:
            text = text.rstrip("0").rstrip(".")
        return text or "0"

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
    def validate_amount(amount):

        if isinstance(amount, bool):
            return False

        try:
            value = Decimal(str(amount))

            return (
                value.is_finite()
                and value > 0
            )

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
        network="BSC_MAINNET"
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

        if sender.strip().lower() == receiver.strip().lower():
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
        network="BSC_MAINNET",
        idempotency_key=None
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

        if idempotency_key is not None:

            if (
                not isinstance(idempotency_key, str)
                or not idempotency_key.strip()
                or len(idempotency_key) > 128
            ):
                return {
                    "success": False,
                    "status": "INVALID_IDEMPOTENCY_KEY"
                }

        normalized_sender = sender.strip().lower()
        normalized_receiver = receiver.strip().lower()
        normalized_amount = self._format_decimal(Decimal(str(amount).strip()))
        normalized_asset = asset.strip().upper()
        normalized_network = network.strip().upper()

        fingerprint_data = {
            "chain_id": self.chain_id,
            "sender": normalized_sender,
            "receiver": normalized_receiver,
            "amount": normalized_amount,
            "asset": normalized_asset,
            "network": normalized_network
        }

        fingerprint = self.calculate_integrity_hash(
            fingerprint_data
        )

        with self.lock:

            if idempotency_key is not None:

                clean_key = idempotency_key.strip()
                scope = normalized_sender + ":" + clean_key

                existing = self.idempotency_records.get(scope)

                if existing:

                    if existing["fingerprint"] != fingerprint:
                        return {
                            "success": False,
                            "status": "IDEMPOTENCY_KEY_CONFLICT"
                        }

                    return {
                        "success": False,
                        "status": "DUPLICATE_TRANSACTION",
                        "original_transaction_id": existing["transaction_id"]
                    }

            transaction_id = self.generate_transaction_id()

            transaction = {
                "transaction_id": transaction_id,
                "chain_id": self.chain_id,
                "sender": normalized_sender,
                "receiver": normalized_receiver,
                "amount": normalized_amount,
                "asset": normalized_asset,
                "network": normalized_network,
                "timestamp": self._now_ts(),
                "status": "PENDING"
            }

            integrity_hash = self.calculate_integrity_hash(
                transaction
            )

            self.transactions[transaction_id] = {
                "data": transaction,
                "integrity_hash": integrity_hash
            }

            if idempotency_key is not None:

                clean_key = idempotency_key.strip()
                scope = normalized_sender + ":" + clean_key

                self.idempotency_records[scope] = {
                    "fingerprint": fingerprint,
                    "transaction_id": transaction_id
                }

            return {
                "success": True,
                "status": "TRANSACTION_CREATED",
                "transaction": transaction.copy(),
                "integrity_hash": integrity_hash
            }

    def verify_integrity(self, transaction_id):

        with self.lock:

            record = self.transactions.get(transaction_id)

            if not record:
                return False

            current_hash = self.calculate_integrity_hash(
                record["data"]
            )

            return current_hash == record["integrity_hash"]

    def update_transaction_status(
        self,
        transaction_id,
        new_status
    ):

        if new_status not in self.VALID_STATUSES:
            return False

        with self.lock:

            record = self.transactions.get(transaction_id)

            if not record:
                return False

            if not self.verify_integrity(transaction_id):
                return False

            current_status = record["data"]["status"]

            allowed_transitions = {
                "PENDING": {"VERIFIED", "REJECTED"},
                "VERIFIED": set(),
                "REJECTED": set()
            }

            if new_status not in allowed_transitions[current_status]:
                return False

            record["data"]["status"] = new_status

            record["integrity_hash"] = (
                self.calculate_integrity_hash(record["data"])
            )

            return True

    def get_transaction(self, transaction_id):

        with self.lock:

            record = self.transactions.get(transaction_id)

            if not record:
                return None

            return record["data"].copy()

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Transaction Security Engine",
            "version": cls.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "address_validation": True,
            "amount_validation": True,
            "integrity_verification": True,
            "idempotency_protection": True,
            "transaction_status_management": True,
            "status": "MAINNET_READY"
        }
