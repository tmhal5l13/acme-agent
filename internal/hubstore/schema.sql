CREATE TABLE IF NOT EXISTS schema_meta (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);
INSERT OR IGNORE INTO schema_meta (id, version) VALUES (1, 4);

-- Observed state only, reported by spokes via checkin. Desired state (which
-- domains, which DNS provider, renewal policy) lives in the hub's
-- config.yaml, not here — see config.HubConfig.
--
-- consecutive_failures and last_success_at (schema version 2) exist
-- because status/last_error/last_checkin_at alone can't answer "is this
-- certificate's renewal actually healthy" — a single "failed" checkin
-- looks identical whether it's spoke 1's first-ever failure or spoke 2's
-- fifteenth in a row, and without last_success_at, there's no way to tell
-- how long a certificate has actually been failing to renew versus just
-- hit one blip. See Store.CheckinActive/CheckinFailed for how these are
-- kept correct — a failed checkin must never overwrite not_before/
-- not_after/serial_number, which describe whatever certificate is still
-- actually installed and valid, not the failed attempt.
CREATE TABLE IF NOT EXISTS spoke_cert_state (
    spoke_id              TEXT NOT NULL,
    name                  TEXT NOT NULL,
    not_before            TIMESTAMP,
    not_after             TIMESTAMP,
    serial_number         TEXT,
    status                TEXT NOT NULL DEFAULT 'unknown'
                              CHECK (status IN ('unknown', 'active', 'failed')),
    last_checkin_at       TIMESTAMP,
    last_error            TEXT,
    consecutive_failures  INTEGER NOT NULL DEFAULT 0,
    last_success_at       TIMESTAMP,
    -- claimed_by/claimed_at/claim_expires_at (schema version 3) implement
    -- a renewal lease: Store.Claim atomically sets these, succeeding only
    -- if no other unexpired claim already exists, so two overlapping
    -- attempts for the same certificate (e.g. two processes of what's
    -- supposed to be one spoke running concurrently after a botched
    -- restart) can't both proceed with a real ACME order at once. A claim
    -- that's never released (the holder crashed mid-attempt) self-expires
    -- via claim_expires_at rather than blocking retries forever - see
    -- Store.Claim/ReleaseClaim.
    claimed_by            TEXT,
    claimed_at            TIMESTAMP,
    claim_expires_at      TIMESTAMP,
    PRIMARY KEY (spoke_id, name)
);

-- enrollment_tokens (schema version 4) backs low-friction spoke enrollment:
-- a one-time secret, minted by `acme-hub --generate-token`, redeemed by
-- `acme-spoke --load-token` against POST /v1/enroll. Deliberately holds no
-- cert/domain/dns_provider assignment - that already lives in the hub's
-- config.yaml (config.HubConfig.Spokes) once the operator pastes the
-- generated snippet and reloads, and reading it live at redemption time
-- (rather than a second, potentially-stale copy here) is what guarantees
-- it can never drift out of sync with the one real source of desired
-- state. secret is stored in cleartext, same as every bearer token in
-- config.yaml - see internal/hubapi/auth.go's authorize doc comment for
-- why a plain lookup (not hashing) is this project's established pattern
-- for these.
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    secret        TEXT PRIMARY KEY,
    spoke_id      TEXT NOT NULL,
    bearer_token  TEXT NOT NULL,
    created_at    TIMESTAMP NOT NULL,
    expires_at    TIMESTAMP NOT NULL,
    redeemed_at   TIMESTAMP
);
