"""
VOIN CLOUDFLARE D1 STORAGE ENGINE V1.0.0

Features:
- Cloudflare D1 connection
- Persistent nonce storage
- Persistent challenge storage
- Security event persistence
- Wallet security event retrieval
- Async database operations
"""

import hashlib
import json
import time


class VOIND1StorageEngine:

    VERSION = "1.0.0"

    def __init__(self, database):

        if database is None:
            raise ValueError(
                "D1 database binding is required"
            )

        self.database = database

    # ----------------------------------------------
    # DATABASE HELPERS
    # ----------------------------------------------

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

        return result

    async def _all(self, sql, params=()):

        statement = self.database.prepare(sql)

        if params:
            statement = statement.bind(*params)

        result = await statement.all()

        return [
            dict(row)
            for row in result.results
        ]

    # ----------------------------------------------
    # INTERNAL HELPERS
    # ----------------------------------------------

    @staticmethod
    def _normalize_wallet(wallet):

        if not isinstance(wallet, str):
            raise ValueError("Invalid wallet address")

        wallet = wallet.strip()

        if not wallet:
            raise ValueError("Empty wallet address")

        return wallet.lower()

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

        return json.dumps(
            details,
            sort_keys=True
        )

    # ----------------------------------------------
    # NONCE STORAGE
    # ----------------------------------------------

    async def save_nonce(self, wallet_address, nonce):

        wallet = self._normalize_wallet(wallet_address)
        nonce_hash = self._hash_nonce(nonce)
        timestamp = int(time.time())

        await self._run(
            """
            INSERT INTO nonces (
                wallet_address,
                nonce_hash,
                created_at,
                used
            )
            VALUES (?, ?, ?, 0)
            """,
            (wallet, nonce_hash, timestamp)
        )

        await self.log_event(
            "NONCE_CREATED",
            wallet_address=wallet
        )

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
            (wallet, nonce_hash)
        )

        return result.meta.changes == 1

    # ----------------------------------------------
    # CHALLENGE STORAGE
    # ----------------------------------------------

    async def create_challenge_atomic(
        self,
        challenge_id,
        wallet_address,
        nonce,
        message,
        expires_at
    ):

        wallet = self._normalize_wallet(wallet_address)

        if not isinstance(challenge_id, str) or not challenge_id:
            raise ValueError("Invalid challenge ID")

        if not isinstance(message, str) or not message:
            raise ValueError("Invalid challenge message")

        if (
            isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
            or expires_at <= int(time.time())
        ):
            raise ValueError("Invalid expiration")

        nonce_hash = self._hash_nonce(nonce)
        timestamp = int(time.time())

        # D1 batch executes statements transactionally.
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
            ).bind(wallet, nonce_hash, timestamp),

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
                timestamp,
                expires_at
            )
        ]

        await self.database.batch(statements)

        return True

    async def get_challenge(self, challenge_id):

        return await self._first(
            """
            SELECT *
            FROM challenges
            WHERE challenge_id = ?
            """,
            (challenge_id,)
        )

    async def consume_challenge(
        self,
        challenge_id,
        wallet_address
    ):

        wallet = self._normalize_wallet(wallet_address)

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
                int(time.time())
            )
        )

        return result.meta.changes == 1

    # ----------------------------------------------
    # SECURITY EVENTS
    # ----------------------------------------------

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
                int(time.time()),
                self._serialize_details(details)
            )
        )

        return True

    async def get_security_events(self, limit=100):

        self._validate_limit(limit)

        return await self._all(
            """
            SELECT *
            FROM security_events
            ORDER BY id DESC
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
        self._validate_limit(limit)

        return await self._all(
            """
            SELECT *
            FROM security_events
            WHERE wallet_address = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (wallet, limit)
        )

    @staticmethod
    def _validate_limit(limit):

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit <= 0
        ):
            raise ValueError("Invalid event limit")

    # ----------------------------------------------
    # ENGINE INFORMATION
    # ----------------------------------------------

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Cloudflare D1 Storage",
            "version": cls.VERSION,
            "database": "Cloudflare D1",
            "persistent_storage": True,
            "async_operations": True,
            "nonce_storage": True,
            "challenge_storage": True,
            "security_event_storage": True,
            "private_key_storage": False,
            "status": "READY_FOR_INTEGRATION"
        }
