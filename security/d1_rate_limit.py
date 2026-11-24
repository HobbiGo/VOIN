"""
VOIN D1 Rate Limit Engine
Version: 1.0.3

Asynchronous wallet rate limiter using Cloudflare D1 (BSC Mainnet / Chain ID 56).
"""

import json
import re
import time

DEFAULT_CHAIN_ID = 56
_ZERO_ADDRESS = "0x" + ("0" * 40)


class VOIND1RateLimitEngine:
    VERSION = "1.0.3"

    def __init__(
        self,
        database,
        max_attempts=5,
        window_seconds=300,
        cooldown_seconds=600,
    ):
        if database is None:
            raise ValueError("D1 database binding is required")

        for name, value in (
            ("max_attempts", max_attempts),
            ("window_seconds", window_seconds),
            ("cooldown_seconds", cooldown_seconds),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
            ):
                raise ValueError(
                    f"{name} must be a positive integer"
                )

        self.database = database
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

    @staticmethod
    def _normalize_wallet(wallet_address, *, allow_zero: bool = False):
        if not isinstance(wallet_address, str):
            raise ValueError("Invalid wallet address")

        wallet = wallet_address.strip().lower()

        if not re.fullmatch(r"0x[a-f0-9]{40}", wallet):
            raise ValueError("Invalid wallet address")

        if not allow_zero and wallet == _ZERO_ADDRESS:
            raise ValueError("Zero address is not allowed")

        return wallet

    async def consume_attempt(self, wallet_address):
        """
        Record one authentication attempt.

        Uses atomic UPSERT to avoid separate SELECT/UPDATE
        race conditions.
        """

        wallet = self._normalize_wallet(wallet_address)
        now = int(time.time())

        reset_condition = """
        (
            (
                wallet_rate_limits.cooldown_until IS NOT NULL
                AND wallet_rate_limits.cooldown_until <= ?
            )
            OR
            (
                wallet_rate_limits.cooldown_until IS NULL
                AND (? - wallet_rate_limits.window_started_at) >= ?
            )
        )
        """

        sql = f"""
        INSERT INTO wallet_rate_limits (
            wallet_address,
            window_started_at,
            attempts,
            cooldown_until,
            updated_at
        )
        VALUES (
            ?,
            ?,
            1,
            CASE
                WHEN ? <= 1 THEN ? + ?
                ELSE NULL
            END,
            ?
        )

        ON CONFLICT(wallet_address) DO UPDATE SET

            window_started_at = CASE
                WHEN {reset_condition} THEN ?
                ELSE wallet_rate_limits.window_started_at
            END,

            attempts = CASE
                WHEN {reset_condition} THEN 1
                ELSE wallet_rate_limits.attempts + 1
            END,

            cooldown_until = CASE
                WHEN wallet_rate_limits.cooldown_until > ?
                    THEN wallet_rate_limits.cooldown_until

                WHEN {reset_condition}
                    THEN CASE
                        WHEN ? <= 1 THEN ? + ?
                        ELSE NULL
                    END

                WHEN wallet_rate_limits.attempts + 1 >= ?
                    THEN ? + ?

                ELSE NULL
            END,

            updated_at = ?

        RETURNING
            wallet_address,
            window_started_at,
            attempts,
            cooldown_until,
            updated_at
        """

        # Exactly 24 parameters for 24 SQL placeholders.
        params = [
            # INSERT VALUES: 6
            wallet,
            now,
            self.max_attempts,
            now,
            self.cooldown_seconds,
            now,

            # window_started_at: 4
            now,
            now,
            self.window_seconds,
            now,

            # attempts: 3
            now,
            now,
            self.window_seconds,

            # cooldown_until: 10
            now,
            now,
            now,
            self.window_seconds,
            self.max_attempts,
            now,
            self.cooldown_seconds,
            self.max_attempts,
            now,
            self.cooldown_seconds,

            # updated_at: 1
            now,
        ]

        row = await (
            self.database
            .prepare(sql)
            .bind(*params)
            .first()
        )

        if row is None:
            raise RuntimeError(
                "D1 rate limit operation failed"
            )

        attempts = int(row["attempts"])
        cooldown_until = row["cooldown_until"]

        blocked = (
            cooldown_until is not None
            and int(cooldown_until) > now
        )

        if blocked:
            await self._record_violation(
                wallet,
                attempts,
                now,
            )

        return {
            "success": True,
            "allowed": not blocked,
            "wallet_address": wallet,
            "attempts": attempts,
            "max_attempts": self.max_attempts,
            "remaining_attempts": max(
                0,
                self.max_attempts - attempts,
            ),
            "cooldown_until": cooldown_until,
            "retry_after": (
                max(0, int(cooldown_until) - now)
                if blocked else 0
            ),
        }

    async def _record_violation(
        self,
        wallet,
        attempts,
        now,
    ):
        details = {
            "attempts": attempts,
            "max_attempts": self.max_attempts,
            "cooldown_seconds": self.cooldown_seconds,
            "chain_id": DEFAULT_CHAIN_ID,
            "source": "VOIND1RateLimitEngine",
            "version": self.VERSION,
        }

        sql = """
        INSERT INTO security_events (
            event_type,
            wallet_address,
            reference_id,
            created_at,
            details
        )
        VALUES (?, ?, NULL, ?, ?)
        """

        await (
            self.database
            .prepare(sql)
            .bind(
                "RATE_LIMIT_EXCEEDED",
                wallet,
                now,
                json.dumps(
                    details,
                    separators=(",", ":"),
                    allow_nan=False,
                ),
            )
            .run()
        )

    async def get_status(self, wallet_address):
        wallet = self._normalize_wallet(wallet_address)
        now = int(time.time())

        sql = """
        SELECT
            wallet_address,
            window_started_at,
            attempts,
            cooldown_until,
            updated_at
        FROM wallet_rate_limits
        WHERE wallet_address = ?
        """

        row = await (
            self.database
            .prepare(sql)
            .bind(wallet)
            .first()
        )

        if row is None:
            return {
                "success": True,
                "wallet_address": wallet,
                "attempts": 0,
                "max_attempts": self.max_attempts,
                "remaining_attempts": self.max_attempts,
                "blocked": False,
                "cooldown_until": None,
                "retry_after": 0,
            }

        cooldown_until = row["cooldown_until"]

        blocked = (
            cooldown_until is not None
            and int(cooldown_until) > now
        )

        attempts = int(row["attempts"])

        return {
            "success": True,
            "wallet_address": wallet,
            "attempts": attempts,
            "max_attempts": self.max_attempts,
            "remaining_attempts": max(
                0,
                self.max_attempts - attempts,
            ),
            "blocked": blocked,
            "cooldown_until": cooldown_until,
            "retry_after": (
                max(0, int(cooldown_until) - now)
                if blocked else 0
            ),
        }

    async def reset_wallet(self, wallet_address):
        wallet = self._normalize_wallet(wallet_address)

        await (
            self.database
            .prepare("""
                DELETE FROM wallet_rate_limits
                WHERE wallet_address = ?
            """)
            .bind(wallet)
            .run()
        )

        return {
            "success": True,
            "wallet_address": wallet,
            "message": "Rate limit state reset",
        }

    def engine_info(self):
        return {
            "engine": "VOIN D1 Rate Limit Engine",
            "version": self.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "storage": "Cloudflare D1",
            "async": True,
            "max_attempts": self.max_attempts,
            "window_seconds": self.window_seconds,
            "cooldown_seconds": self.cooldown_seconds,
            "status": "MAINNET_READY",
        }
