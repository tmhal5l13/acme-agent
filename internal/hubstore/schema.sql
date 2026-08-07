CREATE TABLE IF NOT EXISTS schema_meta (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);
INSERT OR IGNORE INTO schema_meta (id, version) VALUES (1, 1);

-- Observed state only, reported by spokes via checkin. Desired state (which
-- domains, which DNS provider, renewal policy) lives in the hub's
-- config.yaml, not here — see config.HubConfig.
CREATE TABLE IF NOT EXISTS spoke_cert_state (
    spoke_id         TEXT NOT NULL,
    name             TEXT NOT NULL,
    not_before       TIMESTAMP,
    not_after        TIMESTAMP,
    serial_number    TEXT,
    status           TEXT NOT NULL DEFAULT 'unknown'
                         CHECK (status IN ('unknown', 'active', 'failed')),
    last_checkin_at  TIMESTAMP,
    last_error       TEXT,
    PRIMARY KEY (spoke_id, name)
);
