CREATE TABLE IF NOT EXISTS schema_meta (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);
INSERT OR IGNORE INTO schema_meta (id, version) VALUES (1, 5);

-- Observed state only, reported by spokes via checkin - which domains,
-- which DNS provider, and renewal policy are desired state, tracked in
-- this same database's spokes/spoke_certs/dns_providers tables below
-- (schema version 5) instead, not here.
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

-- spokes/spoke_tokens/spoke_certs/dns_providers (schema version 5) are the
-- hub's desired state - which spokes exist, their bearer tokens, and which
-- certificates/domains/DNS providers each is authorized to act on - moved
-- here from config.HubConfig.Spokes/.DNSProviders so a write-capable web
-- admin UI (and CLI tools: cmd/acme-onboard, acme-hub --generate-token) can
-- create/edit/delete them directly, taking effect immediately via
-- internal/hubapi.Server.Reload, instead of requiring a hand-edited
-- config.yaml and a restart/SIGHUP. No SQL foreign keys, matching this
-- schema's existing precedent (spoke_cert_state above has none either) -
-- referential integrity (a cert's dns_provider must exist, a DNS provider
-- can't be removed while referenced) is enforced in Go, transactionally,
-- by internal/hubstore's own methods, not the database engine.
CREATE TABLE IF NOT EXISTS spokes (
    id         TEXT PRIMARY KEY,
    created_at TIMESTAMP NOT NULL
);

-- token is the table's primary key, not just spoke_id+token - this is what
-- gives "a bearer token must be globally unique across every spoke" for
-- free (an INSERT for a token already in use by any spoke, including a
-- different one, fails outright), replacing the app-level seenTokens check
-- config.HubConfig.validate() used to make across the whole YAML document
-- at once.
CREATE TABLE IF NOT EXISTS spoke_tokens (
    token      TEXT PRIMARY KEY,
    spoke_id   TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS spoke_certs (
    spoke_id                  TEXT NOT NULL,
    name                      TEXT NOT NULL,
    domains_json              TEXT NOT NULL,              -- JSON array of domain strings
    dns_provider              TEXT NOT NULL,               -- its own column, not buried in domains_json-style JSON, so checking "is this provider still referenced" doesn't need JSON parsing for the common (non-override) case
    domain_dns_providers_json TEXT NOT NULL DEFAULT '{}',  -- JSON object, domain -> dns_providers name override
    renew_before_ns           INTEGER NOT NULL DEFAULT 0,  -- nanoseconds; 0 means "use acme_defaults.renew_before" - mirrors config.Duration's own underlying int64 representation
    PRIMARY KEY (spoke_id, name)
);

CREATE TABLE IF NOT EXISTS dns_providers (
    name        TEXT PRIMARY KEY,
    config_json TEXT NOT NULL   -- config.DNSProviderConfig, JSON-marshaled whole (type + whichever type's credential fields apply) - see internal/hubstore/dnsproviders.go
);
