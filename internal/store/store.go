// Package store persists acme-agent's observed state (ACME accounts and
// per-certificate status) in a local SQLite database.
package store

import (
	"database/sql"
	_ "embed"
	"errors"
	"fmt"

	"github.com/tmhal5l13/acme-agent/internal/secureperm"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// ErrNotFound is returned by Get-style methods when no row matches. Callers
// outside this package should compare against this sentinel rather than
// database/sql's, so store's callers don't need to import database/sql.
var ErrNotFound = errors.New("store: not found")

// Store wraps a SQLite connection pool with acme-agent's schema applied.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path and applies
// the schema. The schema.sql statements all use CREATE TABLE IF NOT EXISTS,
// so this is safe to call on every process start.
//
// See hubstore.Open's doc comment for why _journal_mode=WAL and
// _busy_timeout are set here too: the spoke agent's own writes are mostly
// serialized already (RunOnce processes certs one at a time), but nothing
// prevents a future concurrent access pattern from hitting the same
// immediate-SQLITE_BUSY failure mode without this.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	// The schema.Exec above guarantees the database file itself now exists
	// (sql.Open is lazy and doesn't create it). It holds ACME account keys
	// and certificate state, so it gets the same Windows ACL restriction
	// applied to every other secret-bearing path this codebase writes -
	// see internal/secureperm.
	if err := secureperm.Protect(path); err != nil {
		db.Close()
		return nil, fmt.Errorf("protect database file: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}
