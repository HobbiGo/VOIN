"""
VOIN SECURITY PERSISTENCE ENGINE V1.1

SQLite-based persistent security storage.

Features:
- Persistent challenge storage
- Persistent nonce management
- Atomic challenge consumption
- Atomic nonce consumption
- Atomic authentication consumption
- Security audit event logging

Security note:
This module stores security metadata, not private keys.
"""

import sqlite3
import time
import json
import hashlib
from pathlib import Path


class VOINStorageEngine:

    VERSION = "1.1.0"

    def __init__(self, database_path="voin_security.db"):

        self.database_path = str(database_path)

        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(
                parents=True,
                exist_ok=True
            )

        self._initialize_database()

    def _connect(self):

        connection = sqlite3.connect(
            self.database_path,
            timeout=10,
            isolation_level=None
        )

        connection.row_factory = sqlite3.Row

        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")

        return connection

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

    def save_nonce(self, wallet_address, nonce):

        wallet = self._normalize_wallet(wallet_address)
        nonce_hash = self._hash_nonce(nonce)
        timestamp = int(time.time())

        with self._connect() as connection:

            connection.execute("""
                INSERT INTO nonces (
                    wallet_address,
                    nonce_hash,
                    created_at
                )
                VALUES (?, ?, ?)
            """, (wallet, nonce_hash, timestamp))

        self.log_event(
            "NONCE_CREATED",
            wallet,
            None
        )

        return True

    def consume_nonce(self, wallet_address, nonce):

        wallet = self._normalize_wallet(wallet_address)
        nonce_hash = self._hash_nonce(nonce)

        with self._connect() as connection:

            connection.execute("BEGIN IMMEDIATE")

            cursor = connection.execute("""
                UPDATE nonces
                SET used = 1
                WHERE wallet_address = ?
                AND nonce_hash = ?
                AND used = 0
            """, (wallet, nonce_hash))

            success = cursor.rowcount == 1

            if success:

                connection.execute("""
                    INSERT INTO security_events (
                        event_type,
                        wallet_address,
                        created_at
                    )
                    VALUES (?, ?, ?)
                """, (
                    "NONCE_CONSUMED",
                    wallet,
                    int(time.time())
                ))

            connection.commit()

            return success

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

        if not isinstance(expires_at, int):
            raise ValueError("Invalid expiration")

        nonce_hash = self._hash_nonce(nonce)
        timestamp = int(time.time())

        if expires_at <= timestamp:
            raise ValueError("Challenge already expired")

        with self._connect() as connection:

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

        self.log_event(
            "CHALLENGE_CREATED",
            wallet,
            challenge_id
        )

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

                connection.execute("""
                    INSERT INTO security_events (
                        event_type,
                        wallet_address,
                        reference_id,
                        created_at
                    )
                    VALUES (?, ?, ?, ?)
                """, (
                    "CHALLENGE_CONSUMED",
                    wallet,
                    challenge_id,
                    timestamp
                ))

            connection.commit()

            return success

    def consume_authentication(
        self,
        challenge_id,
        wallet_address,
        nonce
    ):
        """
        Atomically consume challenge and nonce.

        Both records must be valid.
        If either operation fails, neither is consumed.
        """

        wallet = self._normalize_wallet(wallet_address)
        nonce_hash = self._hash_nonce(nonce)
        timestamp = int(time.time())

        with self._connect() as connection:

            try:

                connection.execute("BEGIN IMMEDIATE")

                # Validate and consume challenge.
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

                # Validate and consume nonce.
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

                # Record successful atomic consumption.
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
                    "AUTHENTICATION_CONSUMED",
                    wallet,
                    challenge_id,
                    timestamp,
                    json.dumps({
                        "challenge_consumed": True,
                        "nonce_consumed": True
                    })
                ))

                connection.commit()

                return True

            except Exception:

                connection.rollback()
                raise

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

        if details is not None:
            details = json.dumps(
                details,
                sort_keys=True
            )

        with self._connect() as connection:

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
                wallet,
                reference_id,
                int(time.time()),
                details
            ))

        return True

    def get_security_events(self, limit=100):

        if not isinstance(limit, int) or limit <= 0:
            raise ValueError("Invalid event limit")

        with self._connect() as connection:

            rows = connection.execute("""
                SELECT *
                FROM security_events
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()

        return [dict(row) for row in rows]

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Security Persistence Engine",
            "version": cls.VERSION,
            "database": "SQLite",
            "persistent_challenges": True,
            "persistent_nonces": True,
            "atomic_consumption": True,
            "atomic_authentication": True,
            "security_audit_logging": True,
            "private_key_storage": False,
            "status": "READY_FOR_TESTING"
        }
