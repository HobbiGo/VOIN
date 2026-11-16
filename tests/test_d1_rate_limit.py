@pytest.mark.asyncio
async def test_audit_failure_does_not_undo_rate_limit_state():
    database = FailingAuditDatabase()

    try:
        engine = VOIND1RateLimitEngine(
            database,
            max_attempts=3,
            window_seconds=300,
            cooldown_seconds=60,
        )

        await engine.consume_attempt(WALLET_A)
        await engine.consume_attempt(WALLET_A)

        with pytest.raises(RuntimeError):
            await engine.consume_attempt(WALLET_A)

        row = database.connection.execute("""
            SELECT attempts, cooldown_until
            FROM wallet_rate_limits
            WHERE wallet_address = ?
        """, (WALLET_A,)).fetchone()

        assert row is not None
        assert row["attempts"] == 3
        assert row["cooldown_until"] is not None

    finally:
        database.close()
