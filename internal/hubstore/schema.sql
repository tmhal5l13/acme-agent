CREATE TABLE IF NOT EXISTS schema_meta (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);
INSERT OR IGNORE INTO schema_meta (id, version) VALUES (1, 2);

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
    PRIMARY KEY (spoke_id, name)
);
