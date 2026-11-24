"""
VOIN RATE LIMITING ENGINE V1.0

Features:
- Per-wallet request limiting
- Configurable attempt limits
- Configurable time window
- Temporary cooldown
- SQLite persistence
- Atomic request processing
- SQLite connection lifecycle management
- Security event logging
"""

import re
import sqlite3
import time

from contextlib import closing

_ZERO_ADDRESS = "0x" + ("0" * 40)


class VOINRateLimitEngine:

    VERSION = "1.0.0"

    def __init__(
        self,
        storage,
        max_attempts=5,
        window_seconds=300,
        cooldown_seconds=300
    ):

        self.storage = storage

        self.database_path = str(storage.database_path)

        self.max_attempts = self._validate_positive_int(
            max_attempts,
            "max_attempts"
        )

        self.window_seconds = self._validate_positive_int(
            window_seconds,
            "window_seconds"
        )

        self.cooldown_seconds = self._validate_positive_int(
            cooldown_seconds,
            "cooldown_seconds"
        )

        self._initialize_database()

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

    @staticmethod
    def _validate_positive_int(value, name):

        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"{name} must be a positive integer"
            )

        if value <= 0:
            raise ValueError(
                f"{name} must be greater than zero"
            )

        return value

    @staticmethod
    def _normalize_wallet(wallet_address, *, allow_zero: bool = False):

        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        cleaned = wallet_address.strip().lower()

        if not cleaned or len(cleaned) != 42:
            raise ValueError("Invalid wallet address")

        if not re.fullmatch(r"0x[a-f0-9]{40}", cleaned):
            raise ValueError("Invalid wallet address format")

        if not allow_zero and cleaned == _ZERO_ADDRESS:
            raise ValueError("Zero address is not allowed")

        return cleaned

    # ==========================================
    # SQLITE CONNECTION MANAGEMENT
    # ==========================================

    def _connect(self):

        connection = sqlite3.connect(
            self.database_path,
            timeout=10,
            isolation_level=None
        )

        connection.row_factory = sqlite3.Row

        connection.execute(
            "PRAGMA busy_timeout = 10000"
        )

        return connection

    def _initialize_database(self):

        # Automatically close SQLite connection.

        with closing(self._connect()) as connection:

            connection.execute("""
                CREATE TABLE IF NOT EXISTS wallet_rate_limits (

                    wallet_address TEXT PRIMARY KEY,

                    window_started_at INTEGER NOT NULL,

                    attempt_count INTEGER NOT NULL DEFAULT 0,

                    blocked_until INTEGER NOT NULL DEFAULT 0,

                    updated_at INTEGER NOT NULL

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

    # ==========================================
    # SECURITY EVENT LOGGING
    # ==========================================

    def _log_violation(
        self,
        connection,
        wallet_address,
        details,
        created_at=None
    ):

        ts = int(created_at) if created_at is not None else self._now_ts()

        connection.execute(
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
                "RATE_LIMIT_EXCEEDED",
                wallet_address,
                None,
                ts,
                details
            )
        )

    # ==========================================
    # CONSUME AUTHENTICATION ATTEMPT
    # ==========================================

    def consume_attempt(self, wallet_address):

        wallet = self._normalize_wallet(wallet_address)

        now = self._now_ts()

        connection = self._connect()

        try:

            # Atomic transaction locking.

            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute(
                """
                SELECT *
                FROM wallet_rate_limits
                WHERE wallet_address = ?
                """,
                (wallet,)
            ).fetchone()

            if row is None:

                connection.execute(
                    """
                    INSERT INTO wallet_rate_limits (
                        wallet_address,
                        window_started_at,
                        attempt_count,
                        blocked_until,
                        updated_at
                    )
                    VALUES (?, ?, 0, 0, ?)
                    """,
                    (wallet, now, now)
                )

                window_started = int(now)
                attempts = 0
                blocked_until = 0

            else:

                window_started = int(row["window_started_at"])
                attempts = int(row["attempt_count"])
                blocked_until = int(row["blocked_until"])

            # Existing cooldown is still active.

            if blocked_until > now:

                retry_after = max(1, blocked_until - now)

                self._log_violation(
                    connection,
                    wallet,
                    "Request rejected during active cooldown",
                    created_at=now
                )

                connection.commit()

                return {
                    "allowed": False,
                    "wallet_address": wallet,
                    "attempts": attempts,
                    "remaining": 0,
                    "retry_after": retry_after,
                    "status": "BLOCKED"
                }

            # Start a fresh window after expiration.

            if now - window_started >= self.window_seconds:

                window_started = now
                attempts = 0
                blocked_until = 0

            # Maximum number of allowed attempts reached.

            if attempts >= self.max_attempts:

                blocked_until = now + self.cooldown_seconds

                connection.execute(
                    """
                    UPDATE wallet_rate_limits
                    SET blocked_until = ?,
                        updated_at = ?
                    WHERE wallet_address = ?
                    """,
                    (
                        blocked_until,
                        now,
                        wallet
                    )
                )

                self._log_violation(
                    connection,
                    wallet,
                    "Maximum wallet authentication attempts exceeded",
                    created_at=now
                )

                connection.commit()

                return {
                    "allowed": False,
                    "wallet_address": wallet,
                    "attempts": attempts,
                    "remaining": 0,
                    "retry_after": self.cooldown_seconds,
                    "status": "BLOCKED"
                }

            # Register permitted attempt.

            attempts += 1

            connection.execute(
                """
                UPDATE wallet_rate_limits
                SET window_started_at = ?,
                    attempt_count = ?,
                    blocked_until = 0,
                    updated_at = ?
                WHERE wallet_address = ?
                """,
                (
                    window_started,
                    attempts,
                    now,
                    wallet
                )
            )

            connection.commit()

            return {
                "allowed": True,
                "wallet_address": wallet,
                "attempts": attempts,
                "remaining": max(
                    0,
                    self.max_attempts - attempts
                ),
                "retry_after": 0,
                "status": "ALLOWED"
            }

        except Exception:

            if connection.in_transaction:
                connection.rollback()

            raise

        finally:

            # Always close connection.

            connection.close()

    # ==========================================
    # GET WALLET RATE LIMIT STATUS
    # ==========================================

    def get_status(self, wallet_address):

        wallet = self._normalize_wallet(wallet_address)

        now = self._now_ts()

        # Automatically close SQLite connection.

        with closing(self._connect()) as connection:

            row = connection.execute(
                """
                SELECT *
                FROM wallet_rate_limits
                WHERE wallet_address = ?
                """,
                (wallet,)
            ).fetchone()

        if row is None:

            return {
                "wallet_address": wallet,
                "attempts": 0,
                "remaining": self.max_attempts,
                "blocked": False,
                "retry_after": 0,
                "status": "NORMAL"
            }

        attempts = int(row["attempt_count"])

        blocked_until = int(row["blocked_until"])

        if blocked_until > now:

            return {
                "wallet_address": wallet,
                "attempts": attempts,
                "remaining": 0,
                "blocked": True,
                "retry_after": max(1, blocked_until - now),
                "status": "BLOCKED"
            }

        window_expired = (
            now - int(row["window_started_at"])
            >= self.window_seconds
        )

        if window_expired:

            attempts = 0

        return {
            "wallet_address": wallet,
            "attempts": attempts,
            "remaining": max(
                0,
                self.max_attempts - attempts
            ),
            "blocked": False,
            "retry_after": 0,
            "status": "NORMAL"
        }

    # ==========================================
    # RESET WALLET RATE LIMIT
    # ==========================================

    def reset_wallet(self, wallet_address):

        wallet = self._normalize_wallet(wallet_address)

        # Automatically close SQLite connection.

        with closing(self._connect()) as connection:

            connection.execute(
                """
                DELETE FROM wallet_rate_limits
                WHERE wallet_address = ?
                """,
                (wallet,)
            )

        return True

    # ==========================================
    # ENGINE INFORMATION
    # ==========================================

    def engine_info(self):

        return {
            "engine": "VOIN Rate Limiting Engine",
            "version": self.VERSION,
            "database": self.database_path,
            "max_attempts": self.max_attempts,
            "window_seconds": self.window_seconds,
            "cooldown_seconds": self.cooldown_seconds,
            "status": "MAINNET_READY"
        }
