"""
VOIN SECURITY PERSISTENCE ENGINE V1.4

SQLite-based persistent security storage.

Features:
- Persistent challenge storage
- Persistent nonce management
- Atomic challenge creation
- Nonce ownership validation
- Atomic challenge consumption
- Atomic nonce consumption
- Atomic authentication consumption
- Atomic security event persistence
- Public wallet security event retrieval
- Persistent network peer management
- Atomic network peer event persistence
- Explicit SQLite connection lifecycle management
- Shared in-memory database support
- Backward-compatible storage APIs

Security note:
This module stores security metadata, not private keys.
"""

import sqlite3
import time
import json
import hashlib
import uuid

from pathlib import Path


class _ClosingConnection(sqlite3.Connection):
    """
    SQLite connection that closes automatically
    when leaving a context manager.
    """

    def __exit__(self, exc_type, exc_value, traceback):

        try:
            return super().__exit__(
                exc_type,
                exc_value,
                traceback
            )

        finally:
            self.close()


class VOINStorageEngine:

    VERSION = "1.4.0"

    def __init__(self, database_path="voin_security.db"):

        self.database_path = str(database_path)

        self._memory_uri = None
        self._memory_anchor = None

        if self.database_path == ":memory:":

            self._memory_uri = (
                "file:voin_security_"
                + uuid.uuid4().hex
                + "?mode=memory&cache=shared"
            )

            self._memory_anchor = sqlite3.connect(
                self._memory_uri,
                uri=True,
                timeout=10,
                isolation_level=None
            )

        else:

            Path(self.database_path).parent.mkdir(
                parents=True,
                exist_ok=True
            )

        self._initialize_database()

    # --------------------------------------------------
    # CONNECTION MANAGEMENT
    # --------------------------------------------------

    def _connect(self):

        if self._memory_uri is not None:

            connection = sqlite3.connect(
                self._memory_uri,
                uri=True,
                timeout=10,
                isolation_level=None,
                factory=_ClosingConnection
            )

        else:

            connection = sqlite3.connect(
                self.database_path,
                timeout=10,
                isolation_level=None,
                factory=_ClosingConnection
            )

        connection.row_factory = sqlite3.Row

        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")

        return connection

    def close(self):
        """
        Release the persistent in-memory database anchor.
        File-based database connections are closed automatically.
        """

        if self._memory_anchor is not None:

            self._memory_anchor.close()
            self._memory_anchor = None

    def _initialize_database(self):

        with self._connect() as connection:

            if self.database_path != ":memory:":
                connection.execute("PRAGMA journal_mode = WAL")

            connection.execute("""
                CREATE TABLE IF NOT EXISTS challenges (
                    challenge_id TEXT PRIMARY KEY,
                    wallet_address TEXT NOT NULL,
                    nonce_hash TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS nonces (
                    wallet_address TEXT NOT NULL,
                    nonce_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (wallet_address, nonce_hash)
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    wallet_address TEXT,
                    reference_id TEXT,
                    created_at INTEGER NOT NULL,
                    details TEXT
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS network_peers (
                    peer_id TEXT PRIMARY KEY,
                    endpoint TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK (status IN ('TRUSTED', 'REVOKED')),
                    registered_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS network_security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    peer_id TEXT,
                    created_at INTEGER NOT NULL,
                    details TEXT
                )
            """)

    # --------------------------------------------------
    # INTERNAL HELPERS
    # --------------------------------------------------

    @staticmethod
    def _hash_nonce(nonce):

        if not isinstance(nonce, str) or not nonce:
            raise ValueError("Invalid nonce")

        return hashlib.sha256(
            nonce.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _normalize_wallet(wallet_address):

        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        wallet = wallet_address.strip()

        if not wallet:
            raise ValueError("Empty wallet address")

        return wallet.lower()

    @staticmethod
    def _validate_limit(limit):

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit <= 0
        ):
            raise ValueError("Invalid event limit")

    @staticmethod
    def _serialize_details(details):

        if details is None:
            return None

        return json.dumps(
            details,
            sort_keys=True
        )

    @staticmethod
    def _insert_security_event(
        connection,
        event_type,
        wallet_address=None,
        reference_id=None,
        details=None,
        timestamp=None
    ):

        connection.execute("""
            INSERT INTO security_events (
                event_type,
                wallet_address,
                reference_id,
                created_at,
                details
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            event_type,
            wallet_address,
            reference_id,
            timestamp if timestamp is not None else int(time.time()),
            details
        ))

    @staticmethod
    def _insert_network_event(
        connection,
        event_type,
        peer_id=None,
        details=None,
        timestamp=None
    ):

        connection.execute("""
            INSERT INTO network_security_events (
                event_type,
                peer_id,
                created_at,
                details
            )
            VALUES (?, ?, ?, ?)
        """, (
            event_type,
            peer_id,
            timestamp if timestamp is not None else int(time.time()),
            details
        ))

    # --------------------------------------------------
    # NONCE STORAGE
    # --------------------------------------------------

    def save_nonce(self, wallet_address, nonce):

        wallet = self._normalize_wallet(wallet_address)
        nonce_hash = self._hash_nonce(nonce)
        timestamp = int(time.time())

        with self._connect() as connection:

            try:

                connection.execute("BEGIN IMMEDIATE")

                connection.execute("""
                    INSERT INTO nonces (
                        wallet_address,
                        nonce_hash,
                        created_at
                    )
                    VALUES (?, ?, ?)
                """, (
                    wallet,
                    nonce_hash,
                    timestamp
                ))

                self._insert_security_event(
                    connection,
                    "NONCE_CREATED",
                    wallet,
                    timestamp=timestamp
                )

                connection.commit()

            except Exception:

                connection.rollback()
                raise

        return True

    def consume_nonce(self, wallet_address, nonce):

        wallet = self._normalize_wallet(wallet_address)
        nonce_hash = self._hash_nonce(nonce)
        timestamp = int(time.time())

        with self._connect() as connection:

            try:

                connection.execute("BEGIN IMMEDIATE")

                cursor = connection.execute("""
                    UPDATE nonces
                    SET used = 1
                    WHERE wallet_address = ?
                    AND nonce_hash = ?
                    AND used = 0
                """, (
                    wallet,
                    nonce_hash
                ))

                success = cursor.rowcount == 1

                if success:

                    self._insert_security_event(
                        connection,
                        "NONCE_CONSUMED",
                        wallet,
                        timestamp=timestamp
                    )

                connection.commit()

                return success

            except Exception:

                connection.rollback()
                raise

    # --------------------------------------------------
    # ATOMIC CHALLENGE CREATION
    # --------------------------------------------------

    def create_challenge_atomic(
        self,
        challenge_id,
        wallet_address,
        nonce,
        message,
        expires_at
    ):
        """
        Atomically create nonce, challenge and security events.

        All operations are committed together.

        If any operation fails, the complete transaction
        is rolled back.

        Returns:
            True when all operations succeed.
        """

        wallet = self._normalize_wallet(wallet_address)

        if not isinstance(challenge_id, str) or not challenge_id:
            raise ValueError("Invalid challenge ID")

        if not isinstance(message, str) or not message:
            raise ValueError("Invalid challenge message")

        if (
            isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
        ):
            raise ValueError("Invalid expiration")

        nonce_hash = self._hash_nonce(nonce)
        timestamp = int(time.time())

        if expires_at <= timestamp:
            raise ValueError("Challenge already expired")

        with self._connect() as connection:

            try:

                connection.execute("BEGIN IMMEDIATE")

                # STEP 1: CREATE NONCE

                connection.execute("""
                    INSERT INTO nonces (
                        wallet_address,
                        nonce_hash,
                        created_at,
                        used
                    )
                    VALUES (?, ?, ?, 0)
                """, (
                    wallet,
                    nonce_hash,
                    timestamp
                ))

                # STEP 2: CREATE CHALLENGE

                connection.execute("""
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
                """, (
                    challenge_id,
                    wallet,
                    nonce_hash,
                    message,
                    timestamp,
                    expires_at
                ))

                # STEP 3: RECORD NONCE EVENT

                self._insert_security_event(
                    connection,
                    "NONCE_CREATED",
                    wallet,
                    timestamp=timestamp
                )

                # STEP 4: RECORD CHALLENGE EVENT

                self._insert_security_event(
                    connection,
                    "CHALLENGE_CREATED",
                    wallet,
                    challenge_id,
                    timestamp=timestamp
                )

                # STEP 5: RECORD ATOMIC CREATION EVENT

                self._insert_security_event(
                    connection,
                    "CHALLENGE_CREATED_ATOMIC",
                    wallet,
                    challenge_id,
                    json.dumps({
                        "nonce_created": True,
                        "challenge_created": True,
                        "atomic": True
                    }),
                    timestamp
                )

                # STEP 6: COMMIT

                connection.commit()

                return True

            except Exception:

                connection.rollback()
                raise

    # --------------------------------------------------
    # LEGACY CHALLENGE STORAGE
    # --------------------------------------------------

    def save_challenge(
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
        ):
            raise ValueError("Invalid expiration")

        nonce_hash = self._hash_nonce(nonce)
        timestamp = int(time.time())

        if expires_at <= timestamp:
            raise ValueError("Challenge already expired")

        with self._connect() as connection:

            try:

                connection.execute("BEGIN IMMEDIATE")

                connection.execute("""
                    INSERT INTO challenges (
                        challenge_id,
                        wallet_address,
                        nonce_hash,
                        message,
                        created_at,
                        expires_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    challenge_id,
                    wallet,
                    nonce_hash,
                    message,
                    timestamp,
                    expires_at
                ))

                self._insert_security_event(
                    connection,
                    "CHALLENGE_CREATED",
                    wallet,
                    challenge_id,
                    timestamp=timestamp
                )

                connection.commit()

            except Exception:

                connection.rollback()
                raise

        return True

    def get_challenge(self, challenge_id):

        with self._connect() as connection:

            row = connection.execute("""
                SELECT *
                FROM challenges
                WHERE challenge_id = ?
            """, (challenge_id,)).fetchone()

        if row is None:
            return None

        return dict(row)

    def consume_challenge(self, challenge_id, wallet_address):

        wallet = self._normalize_wallet(wallet_address)
        timestamp = int(time.time())

        with self._connect() as connection:

            try:

                connection.execute("BEGIN IMMEDIATE")

                cursor = connection.execute("""
                    UPDATE challenges
                    SET used = 1
                    WHERE challenge_id = ?
                    AND wallet_address = ?
                    AND used = 0
                    AND expires_at > ?
                """, (
                    challenge_id,
                    wallet,
                    timestamp
                ))

                success = cursor.rowcount == 1

                if success:

                    self._insert_security_event(
                        connection,
                        "CHALLENGE_CONSUMED",
                        wallet,
                        challenge_id,
                        timestamp=timestamp
                    )

                connection.commit()

                return success

            except Exception:

                connection.rollback()
                raise

    # --------------------------------------------------
    # ATOMIC AUTHENTICATION
    # --------------------------------------------------

    def consume_authentication(
        self,
        challenge_id,
        wallet_address,
        nonce
    ):

        wallet = self._normalize_wallet(wallet_address)
        nonce_hash = self._hash_nonce(nonce)
        timestamp = int(time.time())

        with self._connect() as connection:

            try:

                connection.execute("BEGIN IMMEDIATE")

                # CONSUME CHALLENGE

                challenge_cursor = connection.execute("""
                    UPDATE challenges
                    SET used = 1
                    WHERE challenge_id = ?
                    AND wallet_address = ?
                    AND nonce_hash = ?
                    AND used = 0
                    AND expires_at > ?
                """, (
                    challenge_id,
                    wallet,
                    nonce_hash,
                    timestamp
                ))

                if challenge_cursor.rowcount != 1:

                    connection.rollback()
                    return False

                # CONSUME REGISTERED NONCE

                nonce_cursor = connection.execute("""
                    UPDATE nonces
                    SET used = 1
                    WHERE wallet_address = ?
                    AND nonce_hash = ?
                    AND used = 0
                """, (
                    wallet,
                    nonce_hash
                ))

                if nonce_cursor.rowcount != 1:

                    connection.rollback()
                    return False

                # RECORD AUTHENTICATION CONSUMPTION

                self._insert_security_event(
                    connection,
                    "AUTHENTICATION_CONSUMED",
                    wallet,
                    challenge_id,
                    json.dumps({
                        "challenge_consumed": True,
                        "nonce_consumed": True
                    }),
                    timestamp
                )

                connection.commit()

                return True

            except Exception:

                connection.rollback()
                raise

    # --------------------------------------------------
    # GENERAL SECURITY AUDIT
    # --------------------------------------------------

    def log_event(
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

        serialized_details = self._serialize_details(details)

        with self._connect() as connection:

            self._insert_security_event(
                connection,
                event_type,
                wallet,
                reference_id,
                serialized_details
            )

        return True

    def get_security_events(self, limit=100):

        self._validate_limit(limit)

        with self._connect() as connection:

            rows = connection.execute("""
                SELECT *
                FROM security_events
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()

        return [dict(row) for row in rows]

    def get_wallet_security_events(
        self,
        wallet_address,
        limit=100
    ):

        wallet = self._normalize_wallet(wallet_address)
        self._validate_limit(limit)

        with self._connect() as connection:

            rows = connection.execute("""
                SELECT *
                FROM security_events
                WHERE wallet_address = ?
                ORDER BY id DESC
                LIMIT ?
            """, (
                wallet,
                limit
            )).fetchall()

        return [dict(row) for row in rows]

    # --------------------------------------------------
    # NETWORK PEER PERSISTENCE
    # --------------------------------------------------

    def save_network_peer(self, peer_id, endpoint):

        if not isinstance(peer_id, str) or not peer_id:
            raise ValueError("Invalid peer ID")

        if not isinstance(endpoint, str) or not endpoint:
            raise ValueError("Invalid peer endpoint")

        timestamp = int(time.time())

        with self._connect() as connection:

            try:

                connection.execute("BEGIN IMMEDIATE")

                connection.execute("""
                    INSERT INTO network_peers (
                        peer_id,
                        endpoint,
                        status,
                        registered_at,
                        updated_at
                    )
                    VALUES (?, ?, 'TRUSTED', ?, ?)
                """, (
                    peer_id,
                    endpoint,
                    timestamp,
                    timestamp
                ))

                self._insert_network_event(
                    connection,
                    "PEER_REGISTERED",
                    peer_id,
                    timestamp=timestamp
                )

                connection.commit()

            except Exception:

                connection.rollback()
                raise

        return True

    def get_network_peer(self, peer_id):

        with self._connect() as connection:

            row = connection.execute("""
                SELECT *
                FROM network_peers
                WHERE peer_id = ?
            """, (peer_id,)).fetchone()

        if row is None:
            return None

        return dict(row)

    def list_network_peers(self, status=None):

        with self._connect() as connection:

            if status is None:

                rows = connection.execute("""
                    SELECT *
                    FROM network_peers
                    ORDER BY registered_at ASC
                """).fetchall()

            else:

                if status not in {"TRUSTED", "REVOKED"}:
                    raise ValueError("Invalid peer status")

                rows = connection.execute("""
                    SELECT *
                    FROM network_peers
                    WHERE status = ?
                    ORDER BY registered_at ASC
                """, (status,)).fetchall()

        return [dict(row) for row in rows]

    def revoke_network_peer(self, peer_id):

        timestamp = int(time.time())

        with self._connect() as connection:

            try:

                connection.execute("BEGIN IMMEDIATE")

                cursor = connection.execute("""
                    UPDATE network_peers
                    SET status = 'REVOKED',
                        updated_at = ?
                    WHERE peer_id = ?
                    AND status = 'TRUSTED'
                """, (
                    timestamp,
                    peer_id
                ))

                success = cursor.rowcount == 1

                if success:

                    self._insert_network_event(
                        connection,
                        "PEER_REVOKED",
                        peer_id,
                        timestamp=timestamp
                    )

                connection.commit()

                return success

            except Exception:

                connection.rollback()
                raise

    def log_network_event(
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

        serialized_details = self._serialize_details(details)

        with self._connect() as connection:

            self._insert_network_event(
                connection,
                event_type,
                peer_id,
                serialized_details
            )

        return True

    def get_network_security_events(self, limit=100):

        self._validate_limit(limit)

        with self._connect() as connection:

            rows = connection.execute("""
                SELECT *
                FROM network_security_events
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    # --------------------------------------------------
    # ENGINE INFORMATION
    # --------------------------------------------------

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Security Persistence Engine",
            "version": cls.VERSION,
            "database": "SQLite",

            "persistent_challenges": True,
            "persistent_nonces": True,

            "atomic_challenge_creation": True,
            "nonce_ownership_validation": True,

            "atomic_consumption": True,
            "atomic_authentication": True,
            "atomic_event_persistence": True,

            "wallet_event_retrieval": True,
            "persistent_network_peers": True,
            "persistent_network_events": True,

            "private_key_storage": False,

            "backward_compatibility": True,
            "status": "READY_FOR_TESTING"
        }
