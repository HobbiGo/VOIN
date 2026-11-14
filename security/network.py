"""
VOIN NETWORK SECURITY ENGINE V1.0

Provides defensive network peer management.

Features:
- Peer identity validation
- Trusted peer registration
- Endpoint validation
- Duplicate peer prevention
- Peer trust revocation
- Security event logging
- Peer status reporting

Note:
This module manages peer trust metadata.
It does not establish P2P connections.
"""

import re
import time
from urllib.parse import urlparse


class VOINNetworkSecurityEngine:

    VERSION = "1.0.0"

    def __init__(self, audit_engine=None):

        self.audit_engine = audit_engine

        self.trusted_peers = {}
        self.security_events = []

    @staticmethod
    def validate_peer_identity(peer_id):

        if not isinstance(peer_id, str):
            return False

        return bool(
            re.fullmatch(
                r"0x[a-fA-F0-9]{40}",
                peer_id
            )
        )

    @staticmethod
    def validate_endpoint(endpoint):

        if not isinstance(endpoint, str):
            return False

        if not endpoint or endpoint != endpoint.strip():
            return False

        try:
            parsed = urlparse(endpoint)

            if parsed.scheme not in {"http", "https"}:
                return False

            if not parsed.hostname:
                return False

            if parsed.username or parsed.password:
                return False

            if parsed.query or parsed.fragment:
                return False

            if parsed.path not in {"", "/"}:
                return False

            port = parsed.port

            if port is not None and not 1 <= port <= 65535:
                return False

            return True

        except (ValueError, TypeError):
            return False

    def _record_event(self, event_type, peer_id, details=None):

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

    def register_peer(self, peer_id, endpoint):

        if not self.validate_peer_identity(peer_id):

            self._record_event(
                "INVALID_PEER_IDENTITY",
                str(peer_id)
            )

            return {
                "success": False,
                "error": "Invalid peer identity"
            }

        if not self.validate_endpoint(endpoint):

            self._record_event(
                "INVALID_PEER_ENDPOINT",
                peer_id
            )

            return {
                "success": False,
                "error": "Invalid peer endpoint"
            }

        if peer_id in self.trusted_peers:

            self._record_event(
                "DUPLICATE_PEER",
                peer_id
            )

            return {
                "success": False,
                "error": "Peer already registered"
            }

        self.trusted_peers[peer_id] = {
            "peer_id": peer_id,
            "endpoint": endpoint,
            "status": "TRUSTED",
            "registered_at": time.time()
        }

        self._record_event(
            "PEER_REGISTERED",
            peer_id
        )

        return {
            "success": True,
            "peer_id": peer_id,
            "status": "TRUSTED"
        }

    def revoke_peer(self, peer_id):

        if peer_id not in self.trusted_peers:

            self._record_event(
                "UNKNOWN_PEER_REVOCATION",
                str(peer_id)
            )

            return {
                "success": False,
                "error": "Peer not found"
            }

        self.trusted_peers[peer_id]["status"] = "REVOKED"

        self._record_event(
            "PEER_REVOKED",
            peer_id
        )

        return {
            "success": True,
            "peer_id": peer_id,
            "status": "REVOKED"
        }

    def is_trusted_peer(self, peer_id):

        peer = self.trusted_peers.get(peer_id)

        return bool(
            peer
            and peer["status"] == "TRUSTED"
        )

    def get_peer(self, peer_id):

        peer = self.trusted_peers.get(peer_id)

        if peer is None:
            return None

        return dict(peer)

    def list_peers(self):

        return [
            dict(peer)
            for peer in self.trusted_peers.values()
        ]

    def get_security_events(self):

        return [
            dict(event)
            for event in self.security_events
        ]

    def engine_info(self):

        return {
            "engine": "VOIN Network Security Engine",
            "version": self.VERSION,
            "peer_identity_validation": True,
            "trusted_peer_management": True,
            "endpoint_validation": True,
            "duplicate_peer_protection": True,
            "security_event_logging": True,
            "p2p_network": False,
            "status": "READY_FOR_TESTING"
        }
