"""
VOIN CLOUDFLARE D1 STORAGE ENGINE
Version: 1.0.2

Async storage engine for Cloudflare Python Workers.
SQLite local storage remains unchanged.
"""

import hashlib
import json
import time
import math


class VOIND1StorageEngine:

    VERSION = "1.0.2"

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
    def _normalize_wallet(wallet_address):

        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        wallet = wallet_address.strip().lower()

        if len(wallet) != 42 or not wallet.startswith("0x"):
            raise ValueError("Invalid wallet address")

        try:
            int(wallet[2:], 16)
        except ValueError:
            raise ValueError("Invalid wallet address")

        return wallet

    @staticmethod
    def _hash_nonce(nonce):

        if not isinstance(nonce, str) or not nonce:
            raise ValueError("Invalid nonce")

        return hashlib.sha256(
            nonce.encode("utf-8")
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

        now = time.time()

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

        if not isinstance(challenge_id, str) or not challenge_id:
            raise ValueError("Invalid challenge ID")

        if not isinstance(message, str) or not message:
            raise ValueError("Invalid challenge message")

        if isinstance(expires_at, bool) or not isinstance(
            expires_at,
            (int, float)
        ):
            raise ValueError("Invalid challenge expiration")

        try:
            expiration = float(expires_at)

        except (TypeError, ValueError, OverflowError):
            raise ValueError("Invalid challenge expiration")

        # Reject NaN and positive/negative infinity.
        if not math.isfinite(expiration):
            raise ValueError("Invalid challenge expiration")

        now = time.time()

        if expiration <= now:
            raise ValueError(
                "Challenge expiration must be in the future"
            )

        details = json.dumps(
            {
                "challenge_id": challenge_id,
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
            self.database.prepare(
                """
                INSERT INTO challenges (
                    challenge_id,
                    wallet_address,
                    nonce_hash,
                    message,
                    created_at,
                    expires_at,
                    used
                )
                VALUES (?, ?, ?, ?, ?, ?, 0)
                """
            ).bind(
                challenge_id,
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
                challenge_id,
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
                challenge_id,
                now,
                details
            )
        ]

        await self._batch(statements)

        return True

    async def get_challenge(self, challenge_id):

        if not isinstance(challenge_id, str) or not challenge_id:
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
                used
            FROM challenges
            WHERE challenge_id = ?
            LIMIT 1
            """,
            (challenge_id,)
        )

    async def consume_challenge(
        self,
        challenge_id,
        wallet_address
    ):

        wallet = self._normalize_wallet(wallet_address)

        if not isinstance(challenge_id, str) or not challenge_id:
            raise ValueError("Invalid challenge ID")

        result = await self._run(
            """
            UPDATE challenges
            SET used = 1
            WHERE challenge_id = ?
              AND wallet_address = ?
              AND used = 0
              AND expires_at > ?
            """,
            (
                challenge_id,
                wallet,
                time.time()
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

        if not isinstance(challenge_id, str) or not challenge_id:
            raise ValueError("Invalid challenge ID")

        now = time.time()

        # Database trigger performs:
        # 1. Check nonce availability.
        # 2. Consume nonce.
        # 3. Record authentication audit.
        #
        # The trigger and UPDATE must execute within
        # the same database transaction.

        result = await self._run(
            """
            UPDATE challenges
            SET used = 1
            WHERE challenge_id = ?
              AND wallet_address = ?
              AND nonce_hash = ?
              AND used = 0
              AND expires_at > ?
            """,
            (
                challenge_id,
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

        if not isinstance(event_type, str) or not event_type:
            raise ValueError("Invalid event type")

        wallet = None

        if wallet_address is not None:
            wallet = self._normalize_wallet(wallet_address)

        if reference_id is not None:
            if not isinstance(reference_id, str):
                raise ValueError("Invalid reference ID")

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
                event_type,
                wallet,
                reference_id,
                time.time(),
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

        if not isinstance(peer_id, str) or not peer_id:
            raise ValueError("Invalid peer ID")

        if not isinstance(endpoint, str) or not endpoint:
            raise ValueError("Invalid peer endpoint")

        now = time.time()

        # New peers must never be trusted automatically.
        # Verification and approval are separate operations.

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
                peer_id,
                endpoint,
                now,
                now
            )
        )

        return True

    async def get_network_peer(self, peer_id):

        if not isinstance(peer_id, str) or not peer_id:
            raise ValueError("Invalid peer ID")

        return await self._first(
            """
            SELECT *
            FROM network_peers
            WHERE peer_id = ?
            LIMIT 1
            """,
            (peer_id,)
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

        if status not in (
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
            (status,)
        )

    async def revoke_network_peer(self, peer_id):

        if not isinstance(peer_id, str) or not peer_id:
            raise ValueError("Invalid peer ID")

        result = await self._run(
            """
            UPDATE network_peers
            SET status = 'REVOKED',
                updated_at = ?
            WHERE peer_id = ?
              AND status = 'TRUSTED'
            """,
            (
                time.time(),
                peer_id
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

        if not isinstance(event_type, str) or not event_type:
            raise ValueError("Invalid network event type")

        if peer_id is not None:
            if not isinstance(peer_id, str) or not peer_id:
                raise ValueError("Invalid peer ID")

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
                event_type,
                peer_id,
                time.time(),
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
            "database": "Cloudflare D1",
            "storage_type": "SQLite-compatible D1",
            "async": True,
            "atomic_challenge_creation": True,
            "atomic_authentication": True,
            "audit_logging": True,
            "network_peer_storage": True,
            "peer_initial_status": "PENDING",
            "supported_peer_statuses": [
                "PENDING",
                "TRUSTED",
                "REVOKED"
            ],
            "expiration_validation": True,
            "status": "READY_FOR_INTEGRATION"
        }
