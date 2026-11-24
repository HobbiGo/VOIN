"""
VOIN NETWORK COMMUNICATION ENGINE V1.0

Provides a validated message protocol layer (BSC Mainnet / Chain ID 56).

Features:
- Standard message envelope
- Trusted peer authorization
- Message type validation
- Payload validation
- Message size limits
- Timestamp validation
- Message replay protection
- Message handler registration
- Security event logging

Note:
This version implements the communication protocol layer.
It does not establish live network connections.
"""

import json
import re
import time
import uuid

DEFAULT_CHAIN_ID = 56
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = "0x" + ("0" * 40)


class VOINCommunicationEngine:

    VERSION = "1.0.0"

    MAX_MESSAGE_SIZE = 65536
    MAX_TIMESTAMP_AGE = 300
    MAX_FUTURE_OFFSET = 60

    MESSAGE_TYPES = {
        "PING",
        "PONG",
        "HELLO",
        "PEER_STATUS",
        "BLOCK_ANNOUNCEMENT",
        "TRANSACTION_ANNOUNCEMENT",
        "SYNC_REQUEST",
        "SYNC_RESPONSE"
    }

    def __init__(
        self,
        network_engine=None,
        audit_engine=None
    ):

        self.network_engine = network_engine
        self.audit_engine = audit_engine

        self.processed_messages = set()
        self.handlers = {}
        self.security_events = []

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

    @staticmethod
    def _normalize_peer_id(peer_id):
        if not isinstance(peer_id, str):
            return None
        cleaned = peer_id.strip()
        if not cleaned:
            return None
        if _EVM_ADDRESS_RE.match(cleaned):
            normalized = cleaned.lower()
            if normalized == _ZERO_ADDRESS:
                return None
            return normalized
        return cleaned

    # --------------------------------------------------
    # MESSAGE ID VALIDATION
    # --------------------------------------------------

    @staticmethod
    def validate_message_id(message_id):

        if not isinstance(message_id, str):
            return False

        try:
            uuid.UUID(message_id.strip())
            return True

        except (ValueError, TypeError, AttributeError):
            return False

    # --------------------------------------------------
    # PEER AUTHORIZATION
    # --------------------------------------------------

    def is_authorized_peer(self, peer_id):

        if self.network_engine is None:
            return False

        normalized_peer = self._normalize_peer_id(peer_id)
        if normalized_peer is None:
            return False

        return bool(self.network_engine.is_trusted_peer(normalized_peer))

    # --------------------------------------------------
    # EVENT LOGGING
    # --------------------------------------------------

    def _record_event(
        self,
        event_type,
        peer_id=None,
        details=None
    ):

        normalized_peer = self._normalize_peer_id(peer_id) if peer_id is not None else None

        event = {
            "event_type": event_type,
            "peer_id": normalized_peer,
            "details": dict(details) if isinstance(details, dict) else {},
            "timestamp": self._now_ts()
        }

        self.security_events.append(event)

        if self.audit_engine is not None:

            record_method = getattr(
                self.audit_engine,
                "record_event",
                None
            )

            if callable(record_method):
                try:
                    record_method(
                        event_type=event_type,
                        wallet_address=(
                            normalized_peer
                            if isinstance(normalized_peer, str)
                            and _EVM_ADDRESS_RE.match(normalized_peer)
                            else None
                        ),
                        details=event["details"]
                    )
                except Exception:
                    pass

        return event

    # --------------------------------------------------
    # MESSAGE CREATION
    # --------------------------------------------------

    def create_message(
        self,
        sender_id,
        receiver_id,
        message_type,
        payload
    ):

        normalized_sender = self._normalize_peer_id(sender_id)
        normalized_receiver = self._normalize_peer_id(receiver_id)

        if not self.is_authorized_peer(normalized_sender):

            return {
                "success": False,
                "error": "Unauthorized sender"
            }

        if not self.is_authorized_peer(normalized_receiver):

            return {
                "success": False,
                "error": "Unauthorized receiver"
            }

        if not isinstance(message_type, str) or message_type.strip().upper() not in self.MESSAGE_TYPES:

            return {
                "success": False,
                "error": "Unsupported message type"
            }

        if not isinstance(payload, dict):

            return {
                "success": False,
                "error": "Payload must be a dictionary"
            }

        message = {
            "message_id": str(uuid.uuid4()),
            "sender_id": normalized_sender,
            "receiver_id": normalized_receiver,
            "message_type": message_type.strip().upper(),
            "timestamp": self._now_ts(),
            "payload": payload
        }

        try:

            encoded = json.dumps(
                message,
                separators=(",", ":"),
                allow_nan=False
            )

        except (TypeError, ValueError):

            return {
                "success": False,
                "error": "Invalid message payload"
            }

        if len(encoded.encode("utf-8")) > self.MAX_MESSAGE_SIZE:

            return {
                "success": False,
                "error": "Message exceeds maximum size"
            }

        return {
            "success": True,
            "message": message
        }

    # --------------------------------------------------
    # MESSAGE VALIDATION
    # --------------------------------------------------

    def validate_message(self, message):

        if not isinstance(message, dict):
            return False

        required_fields = {
            "message_id",
            "sender_id",
            "receiver_id",
            "message_type",
            "timestamp",
            "payload"
        }

        if set(message.keys()) != required_fields:
            return False

        if not self.validate_message_id(
            message["message_id"]
        ):
            return False

        if not self.is_authorized_peer(
            message["sender_id"]
        ):
            return False

        if not self.is_authorized_peer(
            message["receiver_id"]
        ):
            return False

        if (
            not isinstance(message["message_type"], str)
            or message["message_type"].strip().upper() not in self.MESSAGE_TYPES
        ):
            return False

        if not isinstance(message["payload"], dict):
            return False

        timestamp = message["timestamp"]

        if isinstance(timestamp, bool):
            return False

        if not isinstance(timestamp, (int, float)):
            return False

        now = self._now_ts()

        if timestamp > now + self.MAX_FUTURE_OFFSET:
            return False

        if now - timestamp > self.MAX_TIMESTAMP_AGE:
            return False

        try:

            encoded = json.dumps(
                message,
                separators=(",", ":"),
                allow_nan=False
            )

        except (TypeError, ValueError):

            return False

        if len(encoded.encode("utf-8")) > self.MAX_MESSAGE_SIZE:
            return False

        return True

    # --------------------------------------------------
    # MESSAGE HANDLERS
    # --------------------------------------------------

    def register_handler(self, message_type, handler):

        if not isinstance(message_type, str):
            return False

        normalized_type = message_type.strip().upper()
        if normalized_type not in self.MESSAGE_TYPES:
            return False

        if not callable(handler):
            return False

        self.handlers[normalized_type] = handler

        return True

    # --------------------------------------------------
    # MESSAGE RECEIVING
    # --------------------------------------------------

    def receive_message(
        self,
        message,
        receiving_peer_id
    ):

        normalized_receiver_peer = self._normalize_peer_id(receiving_peer_id)

        if not self.validate_message(message):

            self._record_event(
                "INVALID_NETWORK_MESSAGE",
                normalized_receiver_peer
            )

            return {
                "success": False,
                "error": "Invalid message"
            }

        normalized_sender = self._normalize_peer_id(message["sender_id"])
        normalized_msg_receiver = self._normalize_peer_id(message["receiver_id"])

        if normalized_msg_receiver != normalized_receiver_peer:

            self._record_event(
                "MESSAGE_RECEIVER_MISMATCH",
                normalized_receiver_peer
            )

            return {
                "success": False,
                "error": "Receiver mismatch"
            }

        message_id = message["message_id"].strip()

        if message_id in self.processed_messages:

            self._record_event(
                "MESSAGE_REPLAY_ATTEMPT",
                normalized_sender
            )

            return {
                "success": False,
                "error": "Duplicate message"
            }

        self.processed_messages.add(message_id)

        message_type = message["message_type"].strip().upper()

        handler = self.handlers.get(message_type)

        if handler is None:

            self._record_event(
                "MESSAGE_HANDLER_NOT_FOUND",
                normalized_sender
            )

            return {
                "success": False,
                "error": "Message handler not found"
            }

        try:

            result = handler(message["payload"])

        except Exception:

            self._record_event(
                "MESSAGE_HANDLER_ERROR",
                normalized_sender
            )

            return {
                "success": False,
                "error": "Message processing failed"
            }

        self._record_event(
            "MESSAGE_PROCESSED",
            normalized_sender,
            {
                "message_type": message_type,
                "message_id": message_id
            }
        )

        return {
            "success": True,
            "message_id": message_id,
            "result": result
        }

    # --------------------------------------------------
    # SECURITY EVENTS
    # --------------------------------------------------

    def get_security_events(self):

        return [
            dict(event)
            for event in self.security_events
        ]

    # --------------------------------------------------
    # ENGINE INFORMATION
    # --------------------------------------------------

    def engine_info(self):

        return {
            "engine": "VOIN Network Communication Engine",
            "version": self.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "message_protocol": True,
            "peer_authorization": True,
            "message_validation": True,
            "message_size_limit": self.MAX_MESSAGE_SIZE,
            "replay_protection": True,
            "message_handlers": True,
            "live_network_transport": False,
            "status": "MAINNET_READY"
        }
