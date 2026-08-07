package hubstore

import (
	"database/sql"
	"fmt"
	"time"
)

// CertState is the hub's last-known observed state for one spoke's
// certificate, as reported by that spoke's own checkin call.
type CertState struct {
	SpokeID       string
	Name          string
	NotBefore     sql.NullTime
	NotAfter      sql.NullTime
	SerialNumber  sql.NullString
	Status        string
	LastCheckinAt sql.NullTime
	LastError     sql.NullString
}

// Checkin records what a spoke reports about one of its certificates.
// status is typically "active" (issued successfully) or "failed" (the
// spoke's own attempt to renew failed); checkinErr, if non-nil, is recorded
// as the error the spoke reported.
func (s *Store) Checkin(spokeID, name string, notBefore, notAfter time.Time, serialNumber, status string, checkinErr error) error {
	var errText sql.NullString
	if checkinErr != nil {
		errText = sql.NullString{String: checkinErr.Error(), Valid: true}
	}

	_, err := s.db.Exec(`
		INSERT INTO spoke_cert_state (spoke_id, name, not_before, not_after, serial_number, status, last_checkin_at, last_error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (spoke_id, name) DO UPDATE SET
			not_before      = excluded.not_before,
			not_after       = excluded.not_after,
			serial_number   = excluded.serial_number,
			status          = excluded.status,
			last_checkin_at = excluded.last_checkin_at,
			last_error      = excluded.last_error`,
		spokeID, name, notBefore, notAfter, serialNumber, status, time.Now().UTC(), errText)
	if err != nil {
		return fmt.Errorf("checkin for spoke=%q name=%q: %w", spokeID, name, err)
	}
	return nil
}

// Get returns the last-known state for spoke+name, or ErrNotFound if that
// spoke has never checked in for this certificate — which callers should
// treat as "due" (nothing has ever been issued).
func (s *Store) Get(spokeID, name string) (*CertState, error) {
	row := s.db.QueryRow(`
		SELECT spoke_id, name, not_before, not_after, serial_number, status, last_checkin_at, last_error
		FROM spoke_cert_state WHERE spoke_id = ? AND name = ?`, spokeID, name)

	var cs CertState
	err := row.Scan(&cs.SpokeID, &cs.Name, &cs.NotBefore, &cs.NotAfter, &cs.SerialNumber, &cs.Status, &cs.LastCheckinAt, &cs.LastError)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &cs, nil
}
