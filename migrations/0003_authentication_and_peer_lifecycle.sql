-- =====================================================
-- VOIN SECURITY MIGRATION 0003
-- Authentication and Network Peer Lifecycle
-- =====================================================

-- 1. Add explicit challenge consumption type.
-- Existing records default to CHALLENGE.

ALTER TABLE challenges
ADD COLUMN consumption_type TEXT NOT NULL
DEFAULT 'CHALLENGE'
CHECK (
    consumption_type IN (
        'CHALLENGE',
        'AUTHENTICATION'
    )
);

-- 2. Remove old triggers.

DROP TRIGGER IF EXISTS trg_validate_challenge_nonce;
DROP TRIGGER IF EXISTS trg_consume_challenge_nonce;

-- 3. Validate nonce only for authentication consumption.

CREATE TRIGGER trg_validate_challenge_nonce
BEFORE UPDATE OF used ON challenges
FOR EACH ROW
WHEN
    OLD.used = 0
    AND NEW.used = 1
    AND NEW.consumption_type = 'AUTHENTICATION'
BEGIN

    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1
            FROM nonces
            WHERE wallet_address = NEW.wallet_address
              AND nonce_hash = NEW.nonce_hash
              AND used = 0
        )
        THEN RAISE(
            ABORT,
            'Authentication nonce unavailable'
        )
    END;

END;

-- 4. Consume nonce and create authentication audit
-- only when consumption_type is AUTHENTICATION.

CREATE TRIGGER trg_consume_challenge_nonce
AFTER UPDATE OF used ON challenges
FOR EACH ROW
WHEN
    OLD.used = 0
    AND NEW.used = 1
    AND NEW.consumption_type = 'AUTHENTICATION'
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
        NEW.created_at,
        '{"status":"authenticated"}'
    );

END;

-- 5. Rebuild network_peers to support PENDING.

CREATE TABLE network_peers_new (
    peer_id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (
            status IN (
                'PENDING',
                'TRUSTED',
                'REVOKED'
            )
        ),
    registered_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

INSERT INTO network_peers_new (
    peer_id,
    endpoint,
    status,
    registered_at,
    updated_at
)
SELECT
    peer_id,
    endpoint,
    status,
    registered_at,
    updated_at
FROM network_peers;

DROP TABLE network_peers;

ALTER TABLE network_peers_new
RENAME TO network_peers;

-- 6. Restore peer indexes.

CREATE INDEX IF NOT EXISTS
idx_network_peers_status
ON network_peers(status);

-- =====================================================
-- END MIGRATION 0003
-- =====================================================
