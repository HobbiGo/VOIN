"""
VOIN NETWORK SECURITY ENGINE V1.1

Provides defensive network peer management.

Features:
- Peer identity validation
- Trusted peer registration
- Endpoint validation
- Duplicate peer prevention
- Peer trust revocation
- Security event logging
- Peer status reporting
- SQLite peer persistence
- Peer recovery after restart

Note:
This module manages peer trust metadata.
It does not establish P2P connections
or cryptographically authenticate peers.
"""

import re
import time

from urllib.parse import urlparse


class VOINNetworkSecurityEngine:

    VERSION = "1.1.0"

    def __init__(
        self,
        audit_engine=None,
        storage_engine=None
    ):

        self.audit_engine = audit_engine
        self.storage_engine = storage_engine

        self.trusted_peers = {}
        self.security_events = []

        self._load_persistent_peers()

    # --------------------------------------------------
    # PEER RECOVERY
    # --------------------------------------------------

    def _load_persistent_peers(self):

        if self.storage_engine is None:
            return

        peers = self.storage_engine.list_network_peers()

        for peer in peers:

            peer_id = peer["peer_id"]

            self.trusted_peers[peer_id] = {
                "peer_id": peer_id,
                "endpoint": peer["endpoint"],
                "status": peer["status"],
                "registered_at": peer["registered_at"],
                "updated_at": peer["updated_at"]
            }

    # --------------------------------------------------
    # VALIDATION
    # --------------------------------------------------

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

    # --------------------------------------------------
    # EVENT LOGGING
    # --------------------------------------------------

    def _record_event(
        self,
        event_type,
        peer_id,
        details=None
    ):

        event = {
            "event_type": event_type,
            "peer_id": peer_id,
            "details": details or {},
            "timestamp": time.time()
        }

        self.security_events.append(event)

        if self.storage_engine is not None:

            self.storage_engine.log_network_event(
                event_type,
                peer_id,
                event["details"]
            )

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
    # PEER REGISTRATION
    # --------------------------------------------------

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

        existing_peer = self.trusted_peers.get(peer_id)

        if existing_peer is not None:

            self._record_event(
                "DUPLICATE_PEER",
                peer_id
            )

            return {
                "success": False,
                "error": "Peer already registered"
            }

        if self.storage_engine is not None:

            existing_peer = self.storage_engine.get_network_peer(
                peer_id
            )

            if existing_peer is not None:

                self.trusted_peers[peer_id] = {
                    "peer_id": existing_peer["peer_id"],
                    "endpoint": existing_peer["endpoint"],
                    "status": existing_peer["status"],
                    "registered_at": existing_peer["registered_at"],
                    "updated_at": existing_peer["updated_at"]
                }

                self._record_event(
                    "DUPLICATE_PEER",
                    peer_id
                )

                return {
                    "success": False,
                    "error": "Peer already registered"
                }

            try:

                self.storage_engine.save_network_peer(
                    peer_id,
                    endpoint
                )

            except Exception:

                self._record_event(
                    "PEER_STORAGE_ERROR",
                    peer_id
                )

                return {
                    "success": False,
                    "error": "Peer persistence failed"
                }

            saved_peer = self.storage_engine.get_network_peer(
                peer_id
            )

            registered_at = saved_peer["registered_at"]
            updated_at = saved_peer["updated_at"]

        else:

            registered_at = int(time.time())
            updated_at = registered_at

        self.trusted_peers[peer_id] = {
            "peer_id": peer_id,
            "endpoint": endpoint,
            "status": "TRUSTED",
            "registered_at": registered_at,
            "updated_at": updated_at
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

    # --------------------------------------------------
    # PEER REVOCATION
    # --------------------------------------------------

    def revoke_peer(self, peer_id):

        peer = self.trusted_peers.get(peer_id)

        if peer is None:

            self._record_event(
                "UNKNOWN_PEER_REVOCATION",
                str(peer_id)
            )

            return {
                "success": False,
                "error": "Peer not found"
            }

        if peer["status"] == "REVOKED":

            return {
                "success": False,
                "error": "Peer already revoked"
            }

        if self.storage_engine is not None:

            success = self.storage_engine.revoke_network_peer(
                peer_id
            )

            if not success:

                return {
                    "success": False,
                    "error": "Peer persistence update failed"
                }

            saved_peer = self.storage_engine.get_network_peer(
                peer_id
            )

            peer["updated_at"] = saved_peer["updated_at"]

        else:

            peer["updated_at"] = int(time.time())

        peer["status"] = "REVOKED"

        self._record_event(
            "PEER_REVOKED",
            peer_id
        )

        return {
            "success": True,
            "peer_id": peer_id,
            "status": "REVOKED"
        }

    # --------------------------------------------------
    # PEER STATUS
    # --------------------------------------------------

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
            "engine": "VOIN Network Security Engine",
            "version": self.VERSION,
            "peer_identity_validation": True,
            "trusted_peer_management": True,
            "endpoint_validation": True,
            "duplicate_peer_protection": True,
            "security_event_logging": True,
            "persistent_peer_storage": (
                self.storage_engine is not None
            ),
            "peer_recovery": (
                self.storage_engine is not None
            ),
            "p2p_network": False,
            "status": "READY_FOR_TESTING"
        }
