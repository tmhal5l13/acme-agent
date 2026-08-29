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
	ClaimedBy           sql.NullString
	ClaimedAt           sql.NullTime
	ClaimExpiresAt      sql.NullTime
	LastHookAt          sql.NullTime
	LastHookError       sql.NullString
}

// CheckinActive records a spoke's report of a successful issuance or
// renewal: the certificate fields (not_before/not_after/serial_number) are
// updated to describe the certificate the spoke actually just installed,
// status becomes "active", the failure streak resets to zero, and
// last_success_at is set to now. Also releases any renewal-lease claim
// (see Claim) unconditionally, since a completed attempt — successful or
// not, see CheckinFailed too — is exactly what a claim exists to guard.
// Not identity-guarded against a stale, very-delayed checkin clearing a
// newer claim (a narrow race even in the scenario this exists for: an
// abandoned attempt's checkin arriving late enough to race a retry that
// already reclaimed the lease) — self-expiry via claim_expires_at is the
// actual correctness guarantee; this is a responsiveness optimization on
// top of it, not load-bearing on its own.
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
			last_success_at      = excluded.last_success_at,
			claimed_by           = NULL,
			claimed_at           = NULL,
			claim_expires_at     = NULL`,
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
//
// Also releases any renewal-lease claim unconditionally, same as
// CheckinActive — see that method's doc comment for why this isn't
// identity-guarded and doesn't need to be.
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
			consecutive_failures = excluded.consecutive_failures,
			claimed_by           = NULL,
			claimed_at           = NULL,
			claim_expires_at     = NULL`,
		spokeID, name, now, errText, consecutiveFailures)
	if err != nil {
		return fmt.Errorf("checkin (failed) for spoke=%q name=%q: %w", spokeID, name, err)
	}
	return nil
}

// MarkHookResult records the outcome of a spoke's reload_hook for one of
// its certificates, independent of that certificate's own status (see
// internal/hook for why a hook failure must never be conflated with a
// renewal failure - the same reasoning CheckinActive/CheckinFailed's own
// split already rests on). Mirrors internal/store.Store's identically-named
// method on the spoke side; this is the hub-side twin that makes a hook
// failure visible fleet-wide (GET /v1/status, the admin dashboard) instead
// of sitting invisibly in one spoke's own local database.
//
// Callers pass this whenever a checkin request carries hook status,
// whether or not the same checkin also reports an "active"/"failed"
// certificate status via CheckinActive/CheckinFailed - the two are
// unrelated axes of the same row and this only ever touches its own two
// columns.
func (s *Store) MarkHookResult(spokeID, name string, hookErr error) error {
	var errText sql.NullString
	if hookErr != nil {
		errText = sql.NullString{String: hookErr.Error(), Valid: true}
	}
	now := time.Now().UTC()

	_, err := s.db.Exec(`
		INSERT INTO spoke_cert_state (spoke_id, name, last_hook_at, last_hook_error)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (spoke_id, name) DO UPDATE SET
			last_hook_at    = excluded.last_hook_at,
			last_hook_error = excluded.last_hook_error`,
		spokeID, name, now, errText)
	if err != nil {
		return fmt.Errorf("mark hook result for spoke=%q name=%q: %w", spokeID, name, err)
	}
	return nil
}

// Get returns the last-known state for spoke+name, or ErrNotFound if that
// spoke has never checked in for this certificate — which callers should
// treat as "due" (nothing has ever been issued).
func (s *Store) Get(spokeID, name string) (*CertState, error) {
	row := s.db.QueryRow(`
		SELECT spoke_id, name, not_before, not_after, serial_number, status, last_checkin_at, last_error, consecutive_failures, last_success_at, claimed_by, claimed_at, claim_expires_at, last_hook_at, last_hook_error
		FROM spoke_cert_state WHERE spoke_id = ? AND name = ?`, spokeID, name)

	var cs CertState
	err := row.Scan(
		&cs.SpokeID, &cs.Name, &cs.NotBefore, &cs.NotAfter, &cs.SerialNumber, &cs.Status,
		&cs.LastCheckinAt, &cs.LastError, &cs.ConsecutiveFailures, &cs.LastSuccessAt,
		&cs.ClaimedBy, &cs.ClaimedAt, &cs.ClaimExpiresAt, &cs.LastHookAt, &cs.LastHookError,
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
		SELECT spoke_id, name, not_before, not_after, serial_number, status, last_checkin_at, last_error, consecutive_failures, last_success_at, claimed_by, claimed_at, claim_expires_at, last_hook_at, last_hook_error
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
			&cs.ClaimedBy, &cs.ClaimedAt, &cs.ClaimExpiresAt, &cs.LastHookAt, &cs.LastHookError,
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

// Claim atomically marks (spokeID, name) as claimed by spokeID for
// leaseDuration, returning whether the claim was actually acquired. It
// succeeds either when no row exists yet (a certificate that's never
// checked in - claiming it doesn't require having observed it first) or
// when the existing row's claim_expires_at is unset or already in the
// past; it fails (returns false, nil error) if another claim is already
// active and unexpired.
//
// This is the mechanism that stops two overlapping attempts for the same
// certificate from both proceeding with a real ACME order at once - e.g.
// two processes of what's supposed to be one spoke running concurrently
// after a botched restart, or a slow first attempt still in flight when
// its own next poll tick would otherwise start a second one. A claim
// that's never released (the holder crashed, or simply never checked in)
// self-expires after leaseDuration rather than blocking retries forever -
// see CheckinActive/CheckinFailed, which both release it unconditionally
// as part of recording any completed attempt.
//
// The WHERE clause on the UPSERT's DO UPDATE is what makes this atomic:
// SQLite serializes writes to begin with, but the conditional guard means
// a losing caller's UPDATE is skipped entirely (RowsAffected reports 0)
// rather than racing to overwrite a winner's claim after the fact.
func (s *Store) Claim(spokeID, name string, leaseDuration time.Duration) (bool, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(leaseDuration)

	result, err := s.db.Exec(`
		INSERT INTO spoke_cert_state (spoke_id, name, status, claimed_by, claimed_at, claim_expires_at)
		VALUES (?, ?, 'unknown', ?, ?, ?)
		ON CONFLICT (spoke_id, name) DO UPDATE SET
			claimed_by       = excluded.claimed_by,
			claimed_at       = excluded.claimed_at,
			claim_expires_at = excluded.claim_expires_at
		WHERE spoke_cert_state.claim_expires_at IS NULL OR spoke_cert_state.claim_expires_at < ?`,
		spokeID, name, spokeID, now, expiresAt, now)
	if err != nil {
		return false, fmt.Errorf("claim for spoke=%q name=%q: %w", spokeID, name, err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("claim rows affected for spoke=%q name=%q: %w", spokeID, name, err)
	}
	return affected > 0, nil
}
