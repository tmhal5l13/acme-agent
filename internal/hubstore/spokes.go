package hubstore

import (
	"fmt"
	"time"

	"github.com/tmhal5l13/acme-agent/config"
)

// Spoke is one spoke's full desired state: its identity, every bearer
// token that authenticates as it, and every certificate it's authorized
// to manage - the database-backed equivalent of config.SpokeEntry, keyed
// by spoke ID.
type Spoke struct {
	ID     string
	Tokens []string
	Certs  []config.SpokeCertConfig
}

// CreateSpoke creates a new spoke with exactly one token, both inserted
// in one transaction: a spoke with zero tokens could never authenticate
// at all, so there's no meaningful "spoke exists but has no token yet"
// state to allow. Returns ErrAlreadyExists if spokeID is already taken,
// or ErrTokenInUse if initialToken is already in use by any spoke
// (including a brand-new one being created concurrently - spoke_tokens.token
// being the table's primary key is what makes this check atomic without
// needing a separate guarded UPDATE the way Claim/RedeemEnrollmentToken
// do, since this is a first insert, not a contested update).
func (s *Store) CreateSpoke(spokeID, initialToken string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("create spoke %q: begin transaction: %w", spokeID, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	now := time.Now().UTC()

	if _, err := tx.Exec(`INSERT INTO spokes (id, created_at) VALUES (?, ?)`, spokeID, now); err != nil {
		return fmt.Errorf("create spoke %q: %w", spokeID, ErrAlreadyExists)
	}
	if _, err := tx.Exec(`INSERT INTO spoke_tokens (token, spoke_id, created_at) VALUES (?, ?, ?)`, initialToken, spokeID, now); err != nil {
		return fmt.Errorf("create spoke %q: %w", spokeID, ErrTokenInUse)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("create spoke %q: commit: %w", spokeID, err)
	}
	return nil
}

// DeleteSpoke removes a spoke entirely: its tokens, its certificate
// assignments, any observed renewal state hubstore has recorded for it,
// and any outstanding enrollment token - all in one transaction, so a
// removed spoke never leaves orphaned rows behind for later spoke churn
// to silently accumulate. Returns ErrNotFound if spokeID doesn't exist.
func (s *Store) DeleteSpoke(spokeID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("delete spoke %q: begin transaction: %w", spokeID, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	result, err := tx.Exec(`DELETE FROM spokes WHERE id = ?`, spokeID)
	if err != nil {
		return fmt.Errorf("delete spoke %q: %w", spokeID, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete spoke %q: rows affected: %w", spokeID, err)
	}
	if affected == 0 {
		return fmt.Errorf("delete spoke %q: %w", spokeID, ErrNotFound)
	}

	for _, stmt := range []string{
		`DELETE FROM spoke_tokens WHERE spoke_id = ?`,
		`DELETE FROM spoke_certs WHERE spoke_id = ?`,
		`DELETE FROM spoke_cert_state WHERE spoke_id = ?`,
		`DELETE FROM enrollment_tokens WHERE spoke_id = ?`,
	} {
		if _, err := tx.Exec(stmt, spokeID); err != nil {
			return fmt.Errorf("delete spoke %q: cascade %q: %w", spokeID, stmt, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("delete spoke %q: commit: %w", spokeID, err)
	}
	return nil
}

// AddSpokeToken adds a new token for an existing spoke, alongside
// whatever it already has - see config.SpokeEntry's doc comment on why
// tokens is a list: this is rotation's step 1, adding the new token while
// the old one stays valid during a grace period. Returns ErrNotFound if
// spokeID doesn't exist, or ErrTokenInUse if token is already in use by
// any spoke.
func (s *Store) AddSpokeToken(spokeID, token string) error {
	exists, err := s.SpokeExists(spokeID)
	if err != nil {
		return fmt.Errorf("add token for spoke %q: %w", spokeID, err)
	}
	if !exists {
		return fmt.Errorf("add token for spoke %q: %w", spokeID, ErrNotFound)
	}

	if _, err := s.db.Exec(`INSERT INTO spoke_tokens (token, spoke_id, created_at) VALUES (?, ?, ?)`,
		token, spokeID, time.Now().UTC()); err != nil {
		return fmt.Errorf("add token for spoke %q: %w", spokeID, ErrTokenInUse)
	}
	return nil
}

// RemoveSpokeToken removes one of spokeID's tokens - rotation's step 2,
// once the spoke has confirmed using its new one. Refuses (ErrLastToken)
// if token is the spoke's only remaining one: a spoke with zero tokens
// could never authenticate again, and there'd be no way back except
// deleting and recreating it - cheap to guard against a stray click
// causing that. The count-then-delete happens in one transaction so a
// concurrent removal of a different token for the same spoke can't both
// succeed and leave zero behind.
func (s *Store) RemoveSpokeToken(spokeID, token string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("remove token for spoke %q: begin transaction: %w", spokeID, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM spoke_tokens WHERE spoke_id = ?`, spokeID).Scan(&count); err != nil {
		return fmt.Errorf("remove token for spoke %q: count existing tokens: %w", spokeID, err)
	}
	if count <= 1 {
		return fmt.Errorf("remove token for spoke %q: %w", spokeID, ErrLastToken)
	}

	result, err := tx.Exec(`DELETE FROM spoke_tokens WHERE token = ? AND spoke_id = ?`, token, spokeID)
	if err != nil {
		return fmt.Errorf("remove token for spoke %q: %w", spokeID, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("remove token for spoke %q: rows affected: %w", spokeID, err)
	}
	if affected == 0 {
		return fmt.Errorf("remove token for spoke %q: %w", spokeID, ErrNotFound)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("remove token for spoke %q: commit: %w", spokeID, err)
	}
	return nil
}

// SpokeExists reports whether spokeID has been created.
func (s *Store) SpokeExists(spokeID string) (bool, error) {
	var exists bool
	if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM spokes WHERE id = ?)`, spokeID).Scan(&exists); err != nil {
		return false, fmt.Errorf("check spoke %q exists: %w", spokeID, err)
	}
	return exists, nil
}

// GetSpoke returns one spoke's full desired state - identity, tokens, and
// certificate assignments. Returns ErrNotFound if spokeID doesn't exist.
// Callers that already need every spoke (internal/hubapi.buildState)
// should use AllSpokes instead; this exists for callers (internal/onboard)
// that only ever act on one spoke at a time and don't need the extra
// queries AllSpokes does for the rest.
func (s *Store) GetSpoke(spokeID string) (Spoke, error) {
	exists, err := s.SpokeExists(spokeID)
	if err != nil {
		return Spoke{}, fmt.Errorf("get spoke %q: %w", spokeID, err)
	}
	if !exists {
		return Spoke{}, fmt.Errorf("get spoke %q: %w", spokeID, ErrNotFound)
	}

	tokens, err := s.spokeTokens(spokeID)
	if err != nil {
		return Spoke{}, fmt.Errorf("get spoke %q: %w", spokeID, err)
	}
	certs, err := s.spokeCerts(spokeID)
	if err != nil {
		return Spoke{}, fmt.Errorf("get spoke %q: %w", spokeID, err)
	}
	return Spoke{ID: spokeID, Tokens: tokens, Certs: certs}, nil
}

func (s *Store) spokeTokens(spokeID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT token FROM spoke_tokens WHERE spoke_id = ?`, spokeID)
	if err != nil {
		return nil, fmt.Errorf("query tokens for spoke %q: %w", spokeID, err)
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, fmt.Errorf("scan token row for spoke %q: %w", spokeID, err)
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate token rows for spoke %q: %w", spokeID, err)
	}
	return tokens, nil
}

// AllSpokes returns every spoke's full desired state - identity, tokens,
// and certificate assignments. Three separate queries (spokes, tokens,
// certs) merged in Go, rather than one join, to avoid duplicate-row
// fan-out from a spoke with multiple tokens and multiple certs at once.
func (s *Store) AllSpokes() ([]Spoke, error) {
	ids, err := s.allSpokeIDs()
	if err != nil {
		return nil, err
	}

	tokensBySpoke, err := s.allSpokeTokens()
	if err != nil {
		return nil, err
	}

	certsBySpoke, err := s.allSpokeCerts()
	if err != nil {
		return nil, err
	}

	spokes := make([]Spoke, 0, len(ids))
	for _, id := range ids {
		spokes = append(spokes, Spoke{
			ID:     id,
			Tokens: tokensBySpoke[id],
			Certs:  certsBySpoke[id],
		})
	}
	return spokes, nil
}

func (s *Store) allSpokeIDs() ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM spokes`)
	if err != nil {
		return nil, fmt.Errorf("query all spoke ids: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan spoke id row: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate spoke id rows: %w", err)
	}
	return ids, nil
}

func (s *Store) allSpokeTokens() (map[string][]string, error) {
	rows, err := s.db.Query(`SELECT spoke_id, token FROM spoke_tokens`)
	if err != nil {
		return nil, fmt.Errorf("query all spoke tokens: %w", err)
	}
	defer rows.Close()

	byspoke := make(map[string][]string)
	for rows.Next() {
		var spokeID, token string
		if err := rows.Scan(&spokeID, &token); err != nil {
			return nil, fmt.Errorf("scan spoke token row: %w", err)
		}
		byspoke[spokeID] = append(byspoke[spokeID], token)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate spoke token rows: %w", err)
	}
	return byspoke, nil
}
