// Package hubstore persists both the hub's observed state (what each
// spoke has last reported about its own certificates) and its desired
// state (which spokes exist, their tokens, their certificate/DNS-provider
// assignments, and DNS provider configs) - config.HubConfig only holds
// startup-only settings now (listen_addr, TLS paths, hooks, and so on).
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

// Sentinel errors for the desired-state write methods (spokes.go,
// spokecerts.go, dnsproviders.go) - see each method's own doc comment for
// which of these it can return and why.
var (
	ErrAlreadyExists = errors.New("hubstore: already exists")
	ErrTokenInUse    = errors.New("hubstore: token already in use by another spoke")
	ErrInUse         = errors.New("hubstore: still referenced, cannot remove")
	ErrLastToken     = errors.New("hubstore: refusing to remove a spoke's last token")
)

// Store wraps a SQLite connection pool with the hub's schema applied.
type Store struct {
	db *sql.DB
}

// currentSchemaVersion must match the version schema.sql's INSERT OR IGNORE
// seeds a brand-new database with. Existing databases are brought up to it
// by migrate, since CREATE TABLE IF NOT EXISTS (schema.sql's only tool) does
// nothing for a table that already exists in an older shape.
const currentSchemaVersion = 5

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
//
// _txlock=immediate matters for the same reason, but for a different
// failure mode: a Go sql.Tx (used by every multi-statement write in this
// package — CreateSpoke, DeleteSpoke, RemoveSpokeToken, UpsertSpokeCert —
// as opposed to CheckinActive/Claim's single-statement db.Exec calls)
// defaults to SQLite's own "deferred" transaction mode, which only
// acquires the write lock on that transaction's first actual write
// statement, not at BEGIN. Two such transactions can each successfully
// begin and run their own read statements first (as these all do, to
// check what they're about to write against), then both try to upgrade
// to the write lock at the same moment — a lock-upgrade conflict busy_timeout
// does not retry, and modernc.org/sqlite surfaces it as an immediate
// SQLITE_BUSY. _txlock=immediate makes every sql.Tx acquire the write
// lock at BEGIN instead, so contention shows up as ordinary busy_timeout-retried
// waiting on BEGIN itself, not an unretried mid-transaction upgrade
// failure — the standard fix for this well-documented SQLite behavior in
// any Go application issuing concurrent multi-statement writes.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
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

	if version < 3 {
		if _, err := db.Exec(`
			ALTER TABLE spoke_cert_state ADD COLUMN claimed_by TEXT;
			ALTER TABLE spoke_cert_state ADD COLUMN claimed_at TIMESTAMP;
			ALTER TABLE spoke_cert_state ADD COLUMN claim_expires_at TIMESTAMP;
		`); err != nil {
			return fmt.Errorf("add claimed_by/claimed_at/claim_expires_at columns (v2 -> v3): %w", err)
		}
		if _, err := db.Exec(`UPDATE schema_meta SET version = 3 WHERE id = 1`); err != nil {
			return fmt.Errorf("record schema version 3: %w", err)
		}
	}

	if version < 4 {
		// No ALTER needed - enrollment_tokens is a wholly new table, and
		// schema.sql's CREATE TABLE IF NOT EXISTS above already applies it
		// identically whether this is a fresh database or one upgrading
		// from an earlier version. This block exists purely to keep
		// schema_meta.version's bookkeeping consistent with every other
		// version bump.
		if _, err := db.Exec(`UPDATE schema_meta SET version = 4 WHERE id = 1`); err != nil {
			return fmt.Errorf("record schema version 4: %w", err)
		}
	}

	if version < 5 {
		// No ALTER needed - spokes/spoke_tokens/spoke_certs/dns_providers
		// are all wholly new tables, and schema.sql's CREATE TABLE IF NOT
		// EXISTS above already applies them identically whether this is a
		// fresh database or one upgrading from an earlier version. This
		// block exists purely to keep schema_meta.version's bookkeeping
		// consistent with every other version bump.
		if _, err := db.Exec(`UPDATE schema_meta SET version = 5 WHERE id = 1`); err != nil {
			return fmt.Errorf("record schema version 5: %w", err)
		}
	}

	return nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}
