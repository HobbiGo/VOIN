"""
VOIN NETWORK COMMUNICATION ENGINE V1.0

Provides a validated message protocol layer.

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

    # --------------------------------------------------
    # MESSAGE ID VALIDATION
    # --------------------------------------------------

    @staticmethod
    def validate_message_id(message_id):

        if not isinstance(message_id, str):
            return False

        try:
            uuid.UUID(message_id)
            return True

        except (ValueError, TypeError, AttributeError):
            return False

    # --------------------------------------------------
    # PEER AUTHORIZATION
    # --------------------------------------------------

    def is_authorized_peer(self, peer_id):

        if self.network_engine is None:
            return False

        return self.network_engine.is_trusted_peer(peer_id)

    # --------------------------------------------------
    # EVENT LOGGING
    # --------------------------------------------------

    def _record_event(
        self,
        event_type,
        peer_id=None,
        details=None
    ):

        event = {
            "event_type": event_type,
            "peer_id": peer_id,
            "details": details or {},
            "timestamp": time.time()
        }

        self.security_events.append(event)

        if self.audit_engine is not None:

            record_method = getattr(
                self.audit_engine,
                "record_event",
                None
            )

            if callable(record_method):

                record_method(
                    event_type=event_type,
                    details=event
                )

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

        if not self.is_authorized_peer(sender_id):

            return {
                "success": False,
                "error": "Unauthorized sender"
            }

        if not self.is_authorized_peer(receiver_id):

            return {
                "success": False,
                "error": "Unauthorized receiver"
            }

        if message_type not in self.MESSAGE_TYPES:

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
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "message_type": message_type,
            "timestamp": time.time(),
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

        if message["message_type"] not in self.MESSAGE_TYPES:
            return False

        if not isinstance(message["payload"], dict):
            return False

        timestamp = message["timestamp"]

        if isinstance(timestamp, bool):
            return False

        if not isinstance(timestamp, (int, float)):
            return False

        if timestamp > time.time() + self.MAX_FUTURE_OFFSET:
            return False

        if time.time() - timestamp > self.MAX_TIMESTAMP_AGE:
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

        if message_type not in self.MESSAGE_TYPES:
            return False

        if not callable(handler):
            return False

        self.handlers[message_type] = handler

        return True

    # --------------------------------------------------
    # MESSAGE RECEIVING
    # --------------------------------------------------

    def receive_message(
        self,
        message,
        receiving_peer_id
    ):

        if not self.validate_message(message):

            self._record_event(
                "INVALID_NETWORK_MESSAGE",
                receiving_peer_id
            )

            return {
                "success": False,
                "error": "Invalid message"
            }

        if message["receiver_id"] != receiving_peer_id:

            self._record_event(
                "MESSAGE_RECEIVER_MISMATCH",
                receiving_peer_id
            )

            return {
                "success": False,
                "error": "Receiver mismatch"
            }

        message_id = message["message_id"]

        if message_id in self.processed_messages:

            self._record_event(
                "MESSAGE_REPLAY_ATTEMPT",
                message["sender_id"]
            )

            return {
                "success": False,
                "error": "Duplicate message"
            }

        self.processed_messages.add(message_id)

        message_type = message["message_type"]

        handler = self.handlers.get(message_type)

        if handler is None:

            self._record_event(
                "MESSAGE_HANDLER_NOT_FOUND",
                message["sender_id"]
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
                message["sender_id"]
            )

            return {
                "success": False,
                "error": "Message processing failed"
            }

        self._record_event(
            "MESSAGE_PROCESSED",
            message["sender_id"],
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
            "message_protocol": True,
            "peer_authorization": True,
            "message_validation": True,
            "message_size_limit": self.MAX_MESSAGE_SIZE,
            "replay_protection": True,
            "message_handlers": True,
            "live_network_transport": False,
            "status": "READY_FOR_TESTING"
        }
