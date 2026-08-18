// Package hubstore persists the hub's observed state: what each spoke has
// last reported about its own certificates. Desired state (domains, DNS
// provider, policy) lives in config.HubConfig instead.
package hubstore

import (
	"database/sql"
	_ "embed"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// ErrNotFound is returned by Get-style methods when no row matches.
var ErrNotFound = errors.New("hubstore: not found")

// Store wraps a SQLite connection pool with the hub's schema applied.
type Store struct {
	db *sql.DB
}

// currentSchemaVersion must match the version schema.sql's INSERT OR IGNORE
// seeds a brand-new database with. Existing databases are brought up to it
// by migrate, since CREATE TABLE IF NOT EXISTS (schema.sql's only tool) does
// nothing for a table that already exists in an older shape.
const currentSchemaVersion = 2

// Open opens (creating if necessary) the SQLite database at path, applies
// the schema, and migrates an existing database up to currentSchemaVersion
// if it predates it. schema.sql's statements all use CREATE TABLE IF NOT
// EXISTS, so re-running it is always safe; migrate handles the cases that
// aren't just "create it if missing" — changing the shape of a table that
// may already exist and already hold real data.
//
// The _journal_mode=WAL and _busy_timeout DSN parameters (applied by
// modernc.org/sqlite to every connection it opens, not just the first —
// see its conn.go) matter because database/sql pools multiple connections
// to the same file: without them, SQLite's default rollback-journal mode
// and zero busy_timeout mean one connection holding the write lock makes
// any other connection's concurrent write fail immediately with
// SQLITE_BUSY ("database is locked") rather than waiting for it — a real
// risk here since every spoke checkin is a write, and this hub may be
// serving several spokes at once.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}

	return &Store{db: db}, nil
}

// migrate brings a database created under an older schema version up to
// currentSchemaVersion. Each step is guarded by the version check that
// precedes it, so this is safe to run against a database already at the
// current version (every step is skipped) as well as one several versions
// behind (every step runs in order).
func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`SELECT version FROM schema_meta WHERE id = 1`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	if version < 2 {
		if _, err := db.Exec(`
			ALTER TABLE spoke_cert_state ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;
			ALTER TABLE spoke_cert_state ADD COLUMN last_success_at TIMESTAMP;
		`); err != nil {
			return fmt.Errorf("add consecutive_failures/last_success_at columns (v1 -> v2): %w", err)
		}
		if _, err := db.Exec(`UPDATE schema_meta SET version = 2 WHERE id = 1`); err != nil {
			return fmt.Errorf("record schema version 2: %w", err)
		}
	}

	return nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}
