-- =====================================================
-- VOIN SECURITY MIGRATION 0003
-- Authentication and Network Peer Lifecycle
-- Version: 1.0.1
-- =====================================================

-- 1. Add explicit challenge consumption type.
-- Existing challenges default to CHALLENGE.

ALTER TABLE challenges
ADD COLUMN consumption_type TEXT NOT NULL
DEFAULT 'CHALLENGE'
CHECK (
    consumption_type IN (
        'CHALLENGE',
        'AUTHENTICATION'
    )
);


-- =====================================================
-- 2. Remove previous authentication triggers
-- =====================================================

DROP TRIGGER IF EXISTS trg_validate_challenge_nonce;

DROP TRIGGER IF EXISTS trg_consume_challenge_nonce;


-- =====================================================
-- 3. Validate nonce for authentication only
-- =====================================================

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


-- =====================================================
-- 4. Consume nonce after successful authentication
-- =====================================================

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

        CAST(
            (julianday('now') - 2440587.5) * 86400
            AS REAL
        ),

        '{"status":"authenticated"}'

    );

END;


-- =====================================================
-- 5. Rebuild network_peers
-- Support PENDING, TRUSTED and REVOKED
-- =====================================================

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


-- Preserve existing peer records.

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


-- Replace old table.

DROP TABLE network_peers;


ALTER TABLE network_peers_new

RENAME TO network_peers;


-- =====================================================
-- 6. Restore network peer indexes
-- =====================================================

CREATE INDEX IF NOT EXISTS

idx_network_peers_status

ON network_peers(status);


-- =====================================================
-- END MIGRATION 0003
-- =====================================================
