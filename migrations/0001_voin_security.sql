-- =========================================================
-- VOIN SECURITY D1 SCHEMA
-- Version: 1.0.0
-- Compatible with VOIN SQLite Storage V1.4.0
-- =========================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------
-- 1. NONCES
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS nonces (
    wallet_address TEXT NOT NULL,
    nonce_hash TEXT NOT NULL,
    created_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
        CHECK (used IN (0, 1)),

    PRIMARY KEY (wallet_address, nonce_hash)
);

-- ---------------------------------------------------------
-- 2. CHALLENGES
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS challenges (
    challenge_id TEXT PRIMARY KEY,
    wallet_address TEXT NOT NULL,
    nonce_hash TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
        CHECK (used IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_challenges_wallet
ON challenges(wallet_address);

CREATE INDEX IF NOT EXISTS idx_challenges_expiry
ON challenges(expires_at);

-- ---------------------------------------------------------
-- 3. SECURITY EVENTS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    wallet_address TEXT,
    reference_id TEXT,
    created_at REAL NOT NULL,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_security_events_wallet
ON security_events(wallet_address);

CREATE INDEX IF NOT EXISTS idx_security_events_created
ON security_events(created_at);

CREATE INDEX IF NOT EXISTS idx_security_events_type
ON security_events(event_type);

-- ---------------------------------------------------------
-- 4. NETWORK PEERS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS network_peers (
    peer_id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('TRUSTED', 'REVOKED')),
    registered_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

-- ---------------------------------------------------------
-- 5. NETWORK SECURITY EVENTS
-- ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS network_security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    peer_id TEXT,
    created_at REAL NOT NULL,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_network_events_peer
ON network_security_events(peer_id);

-- =========================================================
-- ATOMIC AUTHENTICATION TRIGGERS
-- =========================================================

-- Pastikan nonce tersedia sebelum challenge dikonsumsi.
CREATE TRIGGER IF NOT EXISTS trg_validate_challenge_nonce
BEFORE UPDATE OF used ON challenges
WHEN OLD.used = 0 AND NEW.used = 1
BEGIN
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1
            FROM nonces
            WHERE wallet_address = NEW.wallet_address
              AND nonce_hash = NEW.nonce_hash
              AND used = 0
        )
        THEN RAISE(ABORT, 'VOIN_NONCE_NOT_AVAILABLE')
    END;
END;

-- Ketika challenge dikonsumsi:
-- 1. Konsumsi nonce yang sesuai.
-- 2. Catat event autentikasi.
-- Semua berjalan dalam transaksi SQL yang sama.
CREATE TRIGGER IF NOT EXISTS trg_consume_challenge_nonce
AFTER UPDATE OF used ON challenges
WHEN OLD.used = 0 AND NEW.used = 1
BEGIN
    UPDATE nonces
    SET used = 1
    WHERE wallet_address = NEW.wallet_address
      AND nonce_hash = NEW.nonce_hash
      AND used = 0;

    INSERT INTO security_events (
        event_type,
        wallet_address,
        reference_id,
        created_at,
        details
    )
    VALUES (
        'AUTHENTICATION_CONSUMED',
        NEW.wallet_address,
        NEW.challenge_id,
        NEW.expires_at,
        '{"challenge_consumed":true,"nonce_consumed":true}'
    );
END;
