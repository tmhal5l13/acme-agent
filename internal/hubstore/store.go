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

// Open opens (creating if necessary) the SQLite database at path and applies
// the schema. schema.sql's statements all use CREATE TABLE IF NOT EXISTS, so
// this is safe to call on every process start.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}
