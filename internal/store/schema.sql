CREATE TABLE IF NOT EXISTS schema_meta (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);
INSERT OR IGNORE INTO schema_meta (id, version) VALUES (1, 1);

-- Keyed by CA directory URL because staging and production are separate ACME servers.
CREATE TABLE IF NOT EXISTS acme_accounts (
    ca_directory_url  TEXT PRIMARY KEY,
    email             TEXT NOT NULL,
    private_key_pem   TEXT NOT NULL,
    registration_uri  TEXT,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One row per managed certificate bundle (config key = "name"). Cert/key file
-- paths are derived deterministically from data_dir + name, not stored here.
CREATE TABLE IF NOT EXISTS certificate_state (
    name                  TEXT PRIMARY KEY,
    not_before            TIMESTAMP,
    not_after             TIMESTAMP,
    serial_number         TEXT,
    status                TEXT NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'active', 'failed')),
    last_issued_at        TIMESTAMP,
    last_attempt_at       TIMESTAMP,
    last_error            TEXT,
    consecutive_failures  INTEGER NOT NULL DEFAULT 0,
    last_hook_at          TIMESTAMP,
    last_hook_error       TEXT,
    updated_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
