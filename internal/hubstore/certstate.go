package hubstore

import (
	"database/sql"
	"fmt"
	"time"
)

// CertState is the hub's last-known observed state for one spoke's
// certificate, as reported by that spoke's own checkin calls.
type CertState struct {
	SpokeID             string
	Name                string
	NotBefore           sql.NullTime
	NotAfter            sql.NullTime
	SerialNumber        sql.NullString
	Status              string
	LastCheckinAt       sql.NullTime
	LastError           sql.NullString
	ConsecutiveFailures int
	LastSuccessAt       sql.NullTime
}

// CheckinActive records a spoke's report of a successful issuance or
// renewal: the certificate fields (not_before/not_after/serial_number) are
// updated to describe the certificate the spoke actually just installed,
// status becomes "active", the failure streak resets to zero, and
// last_success_at is set to now.
func (s *Store) CheckinActive(spokeID, name string, notBefore, notAfter time.Time, serialNumber string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO spoke_cert_state (spoke_id, name, not_before, not_after, serial_number, status, last_checkin_at, last_error, consecutive_failures, last_success_at)
		VALUES (?, ?, ?, ?, ?, 'active', ?, NULL, 0, ?)
		ON CONFLICT (spoke_id, name) DO UPDATE SET
			not_before           = excluded.not_before,
			not_after            = excluded.not_after,
			serial_number        = excluded.serial_number,
			status               = 'active',
			last_checkin_at      = excluded.last_checkin_at,
			last_error           = NULL,
			consecutive_failures = 0,
			last_success_at      = excluded.last_success_at`,
		spokeID, name, notBefore, notAfter, serialNumber, now, now)
	if err != nil {
		return fmt.Errorf("checkin (active) for spoke=%q name=%q: %w", spokeID, name, err)
	}
	return nil
}

// CheckinFailed records a spoke's report of a failed issuance or renewal
// attempt: status becomes "failed", last_error and consecutiveFailures
// (the spoke's own local failure-streak count — see internal/store's
// identically-named field, which this mirrors) are recorded, and
// last_checkin_at advances, same as a successful checkin.
//
// Deliberately does NOT touch not_before/not_after/serial_number/
// last_success_at. Those describe whatever certificate the spoke actually
// has installed right now — which a failed *renewal* attempt doesn't
// change, since the previous certificate (if any) is still sitting there,
// still valid, until it actually expires. Overwriting them here (the bug
// this split fixed) would make the hub believe a certificate had no known
// expiry the moment a single renewal attempt failed, even though the
// installed certificate might still be weeks from expiring.
func (s *Store) CheckinFailed(spokeID, name string, checkinErr error, consecutiveFailures int) error {
	var errText sql.NullString
	if checkinErr != nil {
		errText = sql.NullString{String: checkinErr.Error(), Valid: true}
	}
	now := time.Now().UTC()

	_, err := s.db.Exec(`
		INSERT INTO spoke_cert_state (spoke_id, name, status, last_checkin_at, last_error, consecutive_failures)
		VALUES (?, ?, 'failed', ?, ?, ?)
		ON CONFLICT (spoke_id, name) DO UPDATE SET
			status               = 'failed',
			last_checkin_at      = excluded.last_checkin_at,
			last_error           = excluded.last_error,
			consecutive_failures = excluded.consecutive_failures`,
		spokeID, name, now, errText, consecutiveFailures)
	if err != nil {
		return fmt.Errorf("checkin (failed) for spoke=%q name=%q: %w", spokeID, name, err)
	}
	return nil
}

// Get returns the last-known state for spoke+name, or ErrNotFound if that
// spoke has never checked in for this certificate — which callers should
// treat as "due" (nothing has ever been issued).
func (s *Store) Get(spokeID, name string) (*CertState, error) {
	row := s.db.QueryRow(`
		SELECT spoke_id, name, not_before, not_after, serial_number, status, last_checkin_at, last_error, consecutive_failures, last_success_at
		FROM spoke_cert_state WHERE spoke_id = ? AND name = ?`, spokeID, name)

	var cs CertState
	err := row.Scan(
		&cs.SpokeID, &cs.Name, &cs.NotBefore, &cs.NotAfter, &cs.SerialNumber, &cs.Status,
		&cs.LastCheckinAt, &cs.LastError, &cs.ConsecutiveFailures, &cs.LastSuccessAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &cs, nil
}

// All returns every spoke_cert_state row - every certificate any spoke has
// ever checked in for, across all spokes. Unlike Get, a certificate
// configured but never checked in simply doesn't appear here at all
// (there's no row for it yet); callers wanting to show those too (the
// hub's status API and staleness watchdog both do) need to separately
// cross-reference this against the hub's config.
func (s *Store) All() ([]CertState, error) {
	rows, err := s.db.Query(`
		SELECT spoke_id, name, not_before, not_after, serial_number, status, last_checkin_at, last_error, consecutive_failures, last_success_at
		FROM spoke_cert_state`)
	if err != nil {
		return nil, fmt.Errorf("query all cert states: %w", err)
	}
	defer rows.Close()

	states := []CertState{}
	for rows.Next() {
		var cs CertState
		if err := rows.Scan(
			&cs.SpokeID, &cs.Name, &cs.NotBefore, &cs.NotAfter, &cs.SerialNumber, &cs.Status,
			&cs.LastCheckinAt, &cs.LastError, &cs.ConsecutiveFailures, &cs.LastSuccessAt,
		); err != nil {
			return nil, fmt.Errorf("scan cert state row: %w", err)
		}
		states = append(states, cs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cert state rows: %w", err)
	}
	return states, nil
}
