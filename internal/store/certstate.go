package store

import (
	"database/sql"
	"fmt"
	"time"
)

// CertState is the observed state of one managed certificate, keyed by the
// "name" field from the certificates section of config.yaml.
type CertState struct {
	Name                string
	NotBefore           sql.NullTime
	NotAfter            sql.NullTime
	SerialNumber        sql.NullString
	Status              string
	LastIssuedAt        sql.NullTime
	LastAttemptAt       sql.NullTime
	LastError           sql.NullString
	ConsecutiveFailures int
	LastHookAt          sql.NullTime
	LastHookError       sql.NullString
}

// GetOrCreateCertState returns the existing row for name, or inserts a fresh
// "pending" row (never issued) if none exists yet. Called once per cert on
// every scheduler pass, so a cert defined in config.yaml always has a state
// row without needing a separate provisioning step.
func (s *Store) GetOrCreateCertState(name string) (*CertState, error) {
	cs, err := s.getCertState(name)
	if err == nil {
		return cs, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	_, err = s.db.Exec(
		`INSERT INTO certificate_state (name, status, updated_at) VALUES (?, 'pending', ?)`,
		name, time.Now().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("insert certificate_state for %q: %w", name, err)
	}

	return s.getCertState(name)
}

// MarkIssued records a successful issuance/renewal: status becomes "active",
// the failure streak resets, and the certificate's validity window and
// serial are recorded so the scheduler can compute when it's next due.
func (s *Store) MarkIssued(name string, notBefore, notAfter time.Time, serialNumber string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		UPDATE certificate_state
		SET status = 'active',
		    not_before = ?, not_after = ?, serial_number = ?,
		    last_issued_at = ?, last_attempt_at = ?,
		    last_error = NULL, consecutive_failures = 0,
		    updated_at = ?
		WHERE name = ?`,
		notBefore, notAfter, serialNumber, now, now, now, name)
	if err != nil {
		return fmt.Errorf("mark issued for %q: %w", name, err)
	}
	return nil
}

// MarkFailed records a failed issuance/renewal attempt: status becomes
// "failed", the failure streak increments (driving the scheduler's
// exponential backoff), and the error is recorded for operator visibility.
// Returns the failure streak's new value (after this increment) so callers
// can report it to the hub without a separate read — see
// internal/spokeagent's fail(), which is the only caller that needs it.
func (s *Store) MarkFailed(name string, attemptErr error) (int, error) {
	now := time.Now().UTC()
	var consecutiveFailures int
	err := s.db.QueryRow(`
		UPDATE certificate_state
		SET status = 'failed',
		    last_attempt_at = ?, last_error = ?,
		    consecutive_failures = consecutive_failures + 1,
		    updated_at = ?
		WHERE name = ?
		RETURNING consecutive_failures`,
		now, attemptErr.Error(), now, name).Scan(&consecutiveFailures)
	if err != nil {
		return 0, fmt.Errorf("mark failed for %q: %w", name, err)
	}
	return consecutiveFailures, nil
}

// MarkHookResult records the outcome of the post-issuance reload hook,
// independent of the certificate's own status (see internal/hook for why a
// hook failure must not roll back an otherwise-successful issuance).
func (s *Store) MarkHookResult(name string, hookErr error) error {
	now := time.Now().UTC()
	var errText sql.NullString
	if hookErr != nil {
		errText = sql.NullString{String: hookErr.Error(), Valid: true}
	}
	_, err := s.db.Exec(`
		UPDATE certificate_state
		SET last_hook_at = ?, last_hook_error = ?, updated_at = ?
		WHERE name = ?`,
		now, errText, now, name)
	if err != nil {
		return fmt.Errorf("mark hook result for %q: %w", name, err)
	}
	return nil
}

func (s *Store) getCertState(name string) (*CertState, error) {
	row := s.db.QueryRow(`
		SELECT name, not_before, not_after, serial_number, status,
		       last_issued_at, last_attempt_at, last_error, consecutive_failures,
		       last_hook_at, last_hook_error
		FROM certificate_state WHERE name = ?`, name)

	var cs CertState
	err := row.Scan(
		&cs.Name, &cs.NotBefore, &cs.NotAfter, &cs.SerialNumber, &cs.Status,
		&cs.LastIssuedAt, &cs.LastAttemptAt, &cs.LastError, &cs.ConsecutiveFailures,
		&cs.LastHookAt, &cs.LastHookError,
	)
	if err != nil {
		return nil, err // sql.ErrNoRows is expected/handled by caller
	}
	return &cs, nil
}
