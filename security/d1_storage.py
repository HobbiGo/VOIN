"""
VOIN CLOUDFLARE D1 STORAGE ENGINE
Version: 1.0.3

Async storage engine for Cloudflare Python Workers (BSC Mainnet / Chain ID 56).
SQLite local storage remains unchanged.
"""

import hashlib
import json
import math
import re
import time

DEFAULT_CHAIN_ID = 56
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = "0x" + ("0" * 40)


class VOIND1StorageEngine:

    VERSION = "1.0.3"

    def __init__(self, database):

        if database is None:
            raise ValueError(
                "Cloudflare D1 database binding is required"
            )

        self.database = database

    # =====================================================
    # INTERNAL HELPERS
    # =====================================================

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

    @staticmethod
    def _normalize_wallet(wallet_address, *, allow_zero: bool = False):

        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        wallet = wallet_address.strip().lower()

        if not _EVM_ADDRESS_RE.fullmatch(wallet):
            raise ValueError("Invalid wallet address")

        if not allow_zero and wallet == _ZERO_ADDRESS:
            raise ValueError("Zero address is not allowed")

        return wallet

    @staticmethod
    def _normalize_peer_id(peer_id):

        if not isinstance(peer_id, str):
            raise ValueError("Invalid peer ID")

        cleaned = peer_id.strip()
        if not cleaned:
            raise ValueError("Invalid peer ID")

        if _EVM_ADDRESS_RE.fullmatch(cleaned):
            normalized = cleaned.lower()
            if normalized == _ZERO_ADDRESS:
                raise ValueError("Zero address is not allowed for peer ID")
            return normalized

        return cleaned

    @staticmethod
    def _hash_nonce(nonce):

        if not isinstance(nonce, str) or not nonce.strip():
            raise ValueError("Invalid nonce")

        return hashlib.sha256(
            nonce.strip().encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _serialize_details(details):

        if details is None:
            return None

        try:
            return json.dumps(
                details,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False
            )
        except (TypeError, ValueError):
            raise ValueError("Invalid event details")

    @staticmethod
    def _changes(result):

        try:
            return int(result.meta.changes)
        except (AttributeError, TypeError, ValueError):
            try:
                return int(result["meta"]["changes"])
            except (KeyError, TypeError, ValueError):
                return 0

    @staticmethod
    def _row_to_dict(row):

        if row is None:
            return None

        if isinstance(row, dict):
            return row

        try:
            converted = row.to_py()

            if isinstance(converted, dict):
                return converted

        except (AttributeError, TypeError):
            pass

        try:
            return dict(row)

        except (TypeError, ValueError):
            pass

        try:
            keys = list(row.keys())

            return {
                key: row[key]
                for key in keys
            }

        except (AttributeError, TypeError):
            raise RuntimeError(
                "Unable to convert D1 database row"
            )

    async def _run(self, sql, params=()):

        statement = self.database.prepare(sql)

        if params:
            statement = statement.bind(*params)

        return await statement.run()

    async def _first(self, sql, params=()):

        statement = self.database.prepare(sql)

        if params:
            statement = statement.bind(*params)

        result = await statement.first()

        return self._row_to_dict(result)

    async def _all(self, sql, params=()):

        statement = self.database.prepare(sql)

        if params:
            statement = statement.bind(*params)

        result = await statement.all()

        rows = []

        for row in result.results:
            rows.append(self._row_to_dict(row))

        return rows

    async def _batch(self, statements):

        return await self.database.batch(statements)

    # =====================================================
    # NONCE OPERATIONS
    # =====================================================

    async def save_nonce(self, wallet_address, nonce):

        wallet = self._normalize_wallet(wallet_address)
        nonce_hash = self._hash_nonce(nonce)

        now = self._now_ts()

        statements = [

            self.database.prepare(
                """
                INSERT INTO nonces (
                    wallet_address,
                    nonce_hash,
                    created_at,
                    used
                )
                VALUES (?, ?, ?, 0)
                """
            ).bind(
                wallet,
                nonce_hash,
                now
            ),

            self.database.prepare(
                """
                INSERT INTO security_events (
                    event_type,
                    wallet_address,
                    reference_id,
                    created_at,
                    details
                )
                VALUES (?, ?, ?, ?, ?)
                """
            ).bind(
                "NONCE_CREATED",
                wallet,
                nonce_hash,
                now,
                '{"status":"created"}'
            )
        ]

        await self._batch(statements)

        return True

    async def consume_nonce(self, wallet_address, nonce):

        wallet = self._normalize_wallet(wallet_address)
        nonce_hash = self._hash_nonce(nonce)

        result = await self._run(
            """
            UPDATE nonces
            SET used = 1
            WHERE wallet_address = ?
              AND nonce_hash = ?
              AND used = 0
            """,
            (
                wallet,
                nonce_hash
            )
        )

        return self._changes(result) == 1

    # =====================================================
    # CHALLENGE OPERATIONS
    # =====================================================

    async def create_challenge_atomic(
        self,
        challenge_id,
        wallet_address,
        nonce,
        message,
        expires_at
    ):

        wallet = self._normalize_wallet(wallet_address)
        nonce_hash = self._hash_nonce(nonce)

        if not isinstance(challenge_id, str) or not challenge_id.strip():
            raise ValueError("Invalid challenge ID")

        cleaned_challenge_id = challenge_id.strip()

        if not isinstance(message, str) or not message:
            raise ValueError("Invalid challenge message")

        if isinstance(expires_at, bool) or not isinstance(
            expires_at,
            (int, float)
        ):
            raise ValueError("Invalid challenge expiration")

        try:
            expiration = int(expires_at) if isinstance(expires_at, int) else float(expires_at)

        except (TypeError, ValueError, OverflowError):
            raise ValueError("Invalid challenge expiration")

        if not math.isfinite(expiration):
            raise ValueError("Invalid challenge expiration")

        now = self._now_ts()

        if expiration <= now:
            raise ValueError(
                "Challenge expiration must be in the future"
            )

        details = json.dumps(
            {
                "challenge_id": cleaned_challenge_id,
                "status": "created"
            },
            separators=(",", ":")
        )

        statements = [

            # 1. Create nonce
            self.database.prepare(
                """
                INSERT INTO nonces (
                    wallet_address,
                    nonce_hash,
                    created_at,
                    used
                )
                VALUES (?, ?, ?, 0)
                """
            ).bind(
                wallet,
                nonce_hash,
                now
            ),

            # 2. Create challenge
            # Default consumption_type is CHALLENGE.
            self.database.prepare(
                """
                INSERT INTO challenges (
                    challenge_id,
                    wallet_address,
                    nonce_hash,
                    message,
                    created_at,
                    expires_at,
                    used,
                    consumption_type
                )
                VALUES (?, ?, ?, ?, ?, ?, 0, 'CHALLENGE')
                """
            ).bind(
                cleaned_challenge_id,
                wallet,
                nonce_hash,
                message,
                now,
                expiration
            ),

            # 3. Nonce audit
            self.database.prepare(
                """
                INSERT INTO security_events (
                    event_type,
                    wallet_address,
                    reference_id,
                    created_at,
                    details
                )
                VALUES (?, ?, ?, ?, ?)
                """
            ).bind(
                "NONCE_CREATED",
                wallet,
                nonce_hash,
                now,
                details
            ),

            # 4. Challenge audit
            self.database.prepare(
                """
                INSERT INTO security_events (
                    event_type,
                    wallet_address,
                    reference_id,
                    created_at,
                    details
                )
                VALUES (?, ?, ?, ?, ?)
                """
            ).bind(
                "CHALLENGE_CREATED",
                wallet,
                cleaned_challenge_id,
                now,
                details
            ),

            # 5. Atomic operation audit
            self.database.prepare(
                """
                INSERT INTO security_events (
                    event_type,
                    wallet_address,
                    reference_id,
                    created_at,
                    details
                )
                VALUES (?, ?, ?, ?, ?)
                """
            ).bind(
                "CHALLENGE_CREATED_ATOMIC",
                wallet,
                cleaned_challenge_id,
                now,
                details
            )
        ]

        await self._batch(statements)

        return True

    async def get_challenge(self, challenge_id):

        if not isinstance(challenge_id, str) or not challenge_id.strip():
            raise ValueError("Invalid challenge ID")

        return await self._first(
            """
            SELECT
                challenge_id,
                wallet_address,
                nonce_hash,
                message,
                created_at,
                expires_at,
                used,
                consumption_type
            FROM challenges
            WHERE challenge_id = ?
            LIMIT 1
            """,
            (challenge_id.strip(),)
        )

    async def consume_challenge(
        self,
        challenge_id,
        wallet_address
    ):

        wallet = self._normalize_wallet(wallet_address)

        if not isinstance(challenge_id, str) or not challenge_id.strip():
            raise ValueError("Invalid challenge ID")

        result = await self._run(
            """
            UPDATE challenges
            SET used = 1,
                consumption_type = 'CHALLENGE'
            WHERE challenge_id = ?
              AND wallet_address = ?
              AND used = 0
              AND expires_at > ?
            """,
            (
                challenge_id.strip(),
                wallet,
                self._now_ts()
            )
        )

        return self._changes(result) == 1

    # =====================================================
    # ATOMIC AUTHENTICATION
    # =====================================================

    async def consume_authentication(
        self,
        challenge_id,
        wallet_address,
        nonce
    ):

        wallet = self._normalize_wallet(wallet_address)
        nonce_hash = self._hash_nonce(nonce)

        if not isinstance(challenge_id, str) or not challenge_id.strip():
            raise ValueError("Invalid challenge ID")

        now = self._now_ts()

        # Migration 0003 trigger performs:
        # 1. Validate matching unused nonce.
        # 2. Consume nonce.
        # 3. Record AUTHENTICATION_CONSUMED.
        #
        # The challenge UPDATE and trigger actions
        # execute as one database statement.

        result = await self._run(
            """
            UPDATE challenges
            SET used = 1,
                consumption_type = 'AUTHENTICATION'
            WHERE challenge_id = ?
              AND wallet_address = ?
              AND nonce_hash = ?
              AND used = 0
              AND expires_at > ?
            """,
            (
                challenge_id.strip(),
                wallet,
                nonce_hash,
                now
            )
        )

        return self._changes(result) == 1

    # =====================================================
    # SECURITY AUDIT
    # =====================================================

    async def log_event(
        self,
        event_type,
        wallet_address=None,
        reference_id=None,
        details=None
    ):

        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("Invalid event type")

        wallet = None

        if wallet_address is not None:
            wallet = self._normalize_wallet(wallet_address)

        cleaned_reference_id = None
        if reference_id is not None:
            if not isinstance(reference_id, str):
                raise ValueError("Invalid reference ID")
            stripped = reference_id.strip()
            cleaned_reference_id = stripped if stripped else None

        serialized = self._serialize_details(details)

        await self._run(
            """
            INSERT INTO security_events (
                event_type,
                wallet_address,
                reference_id,
                created_at,
                details
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event_type.strip().upper(),
                wallet,
                cleaned_reference_id,
                self._now_ts(),
                serialized
            )
        )

        return True

    async def get_security_events(self, limit=100):

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("Invalid event limit")

        if limit < 1 or limit > 1000:
            raise ValueError(
                "Event limit must be between 1 and 1000"
            )

        return await self._all(
            """
            SELECT *
            FROM security_events
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (limit,)
        )

    async def get_wallet_security_events(
        self,
        wallet_address,
        limit=100
    ):

        wallet = self._normalize_wallet(wallet_address)

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("Invalid event limit")

        if limit < 1 or limit > 1000:
            raise ValueError(
                "Event limit must be between 1 and 1000"
            )

        return await self._all(
            """
            SELECT *
            FROM security_events
            WHERE wallet_address = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (
                wallet,
                limit
            )
        )

    # =====================================================
    # NETWORK PEERS
    # =====================================================

    async def save_network_peer(self, peer_id, endpoint):

        normalized_peer = self._normalize_peer_id(peer_id)

        if not isinstance(endpoint, str) or not endpoint.strip():
            raise ValueError("Invalid peer endpoint")

        now = self._now_ts()

        # New peers must never be trusted automatically.

        await self._run(
            """
            INSERT INTO network_peers (
                peer_id,
                endpoint,
                status,
                registered_at,
                updated_at
            )
            VALUES (?, ?, 'PENDING', ?, ?)
            """,
            (
                normalized_peer,
                endpoint.strip(),
                now,
                now
            )
        )

        return True

    async def get_network_peer(self, peer_id):

        normalized_peer = self._normalize_peer_id(peer_id)

        return await self._first(
            """
            SELECT *
            FROM network_peers
            WHERE peer_id = ?
            LIMIT 1
            """,
            (normalized_peer,)
        )

    async def list_network_peers(self, status=None):

        if status is None:

            return await self._all(
                """
                SELECT *
                FROM network_peers
                ORDER BY registered_at DESC
                """
            )

        normalized_status = status.strip().upper() if isinstance(status, str) else status
        if normalized_status not in (
            "PENDING",
            "TRUSTED",
            "REVOKED"
        ):
            raise ValueError("Invalid peer status")

        return await self._all(
            """
            SELECT *
            FROM network_peers
            WHERE status = ?
            ORDER BY registered_at DESC
            """,
            (normalized_status,)
        )

    async def revoke_network_peer(self, peer_id):

        normalized_peer = self._normalize_peer_id(peer_id)

        result = await self._run(
            """
            UPDATE network_peers
            SET status = 'REVOKED',
                updated_at = ?
            WHERE peer_id = ?
              AND status IN ('PENDING', 'TRUSTED')
            """,
            (
                self._now_ts(),
                normalized_peer
            )
        )

        return self._changes(result) == 1

    # =====================================================
    # NETWORK AUDIT
    # =====================================================

    async def log_network_event(
        self,
        event_type,
        peer_id=None,
        details=None
    ):

        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("Invalid network event type")

        normalized_peer = None
        if peer_id is not None:
            normalized_peer = self._normalize_peer_id(peer_id)

        serialized = self._serialize_details(details)

        await self._run(
            """
            INSERT INTO network_security_events (
                event_type,
                peer_id,
                created_at,
                details
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                event_type.strip().upper(),
                normalized_peer,
                self._now_ts(),
                serialized
            )
        )

        return True

    async def get_network_security_events(self, limit=100):

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("Invalid event limit")

        if limit < 1 or limit > 1000:
            raise ValueError(
                "Event limit must be between 1 and 1000"
            )

        return await self._all(
            """
            SELECT *
            FROM network_security_events
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (limit,)
        )

    # =====================================================
    # ENGINE INFORMATION
    # =====================================================

    def engine_info(self):

        return {
            "engine": "VOIND1StorageEngine",
            "version": self.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "database": "Cloudflare D1",
            "storage_type": "SQLite-compatible D1",
            "async": True,
            "atomic_challenge_creation": True,
            "atomic_authentication": True,
            "authentication_nonce_trigger": True,
            "audit_logging": True,
            "network_peer_storage": True,
            "peer_initial_status": "PENDING",
            "supported_peer_statuses": [
                "PENDING",
                "TRUSTED",
                "REVOKED"
            ],
            "peer_revocation": True,
            "expiration_validation": True,
            "status": "MAINNET_READY"
        }
