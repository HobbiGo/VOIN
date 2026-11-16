-- =====================================================
-- VOIN SECURITY EXTENSIONS
-- Migration: 0002
-- Version: 1.0.0
-- =====================================================

-- 1. WALLET RATE LIMITS

CREATE TABLE IF NOT EXISTS wallet_rate_limits (
    wallet_address TEXT PRIMARY KEY,
    window_started_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    cooldown_until INTEGER,
    updated_at INTEGER NOT NULL,

    CHECK (attempts >= 0)
);

CREATE INDEX IF NOT EXISTS
idx_wallet_rate_limits_updated
ON wallet_rate_limits(updated_at);


-- 2. SECURITY ALERTS

CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    event_id INTEGER,
    event_type TEXT NOT NULL,
    wallet_address TEXT,
    risk_level TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    created_at INTEGER NOT NULL,
    acknowledged_at INTEGER,
    resolved_at INTEGER,

    CHECK (
        risk_level IN (
            'LOW',
            'MEDIUM',
            'HIGH',
            'CRITICAL'
        )
    ),

    CHECK (
        status IN (
            'OPEN',
            'ACKNOWLEDGED',
            'RESOLVED'
        )
    )
);

CREATE INDEX IF NOT EXISTS
idx_security_alerts_status
ON security_alerts(status);

CREATE INDEX IF NOT EXISTS
idx_security_alerts_risk
ON security_alerts(risk_level);

CREATE INDEX IF NOT EXISTS
idx_security_alerts_created
ON security_alerts(created_at);

CREATE INDEX IF NOT EXISTS
idx_security_alerts_wallet
ON security_alerts(wallet_address);


-- =====================================================
-- END MIGRATION
-- =====================================================
