package hubstore

import (
	"database/sql"
	"fmt"
	"time"
)

// InsertEnrollmentToken records a freshly-minted enrollment secret.
// expiresAt is normalized to UTC internally, regardless of what the
// caller passes - LookupEnrollmentToken/RedeemEnrollmentToken always
// compare against a UTC "now", and SQLite compares these TIMESTAMP
// columns as text: a local-zone offset (e.g. "-07:00") and a UTC "Z"
// suffix don't sort the way their underlying instants actually compare,
// so every timestamp this package writes needs to consistently be UTC,
// not just the ones this package itself generates.
//
// No collision handling needed for secret - it's generated with the same
// crypto/rand entropy as a bearer token (see onboard.GenerateToken),
// already relied on elsewhere in this project to make collision
// practically impossible.
func (s *Store) InsertEnrollmentToken(secret, spokeID, bearerToken string, expiresAt time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO enrollment_tokens (secret, spoke_id, bearer_token, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`,
		secret, spokeID, bearerToken, time.Now().UTC(), expiresAt.UTC())
	if err != nil {
		return fmt.Errorf("insert enrollment token for spoke=%q: %w", spokeID, err)
	}
	return nil
}

// LookupEnrollmentToken returns the spoke ID and bearer token an
// unexpired, not-yet-redeemed secret is associated with, without
// consuming it. ok=false covers "doesn't exist," "expired," and
// "already redeemed" alike - the same non-distinction RedeemEnrollmentToken
// makes (see its doc comment for why).
//
// This exists separately from RedeemEnrollmentToken specifically so a
// caller (POST /v1/enroll) can check whether the associated spoke is
// actually authorized yet in the hub's current, live desired state
// *before* consuming the one-time secret - redeeming a secret that can't
// yet be fully honored (the write that created the spoke hasn't reloaded
// into hubState yet) would permanently strand the caller's retry once it
// has.
func (s *Store) LookupEnrollmentToken(secret string, now time.Time) (spokeID, bearerToken string, ok bool, err error) {
	row := s.db.QueryRow(`
		SELECT spoke_id, bearer_token FROM enrollment_tokens
		WHERE secret = ? AND redeemed_at IS NULL AND expires_at > ?`, secret, now)
	err = row.Scan(&spokeID, &bearerToken)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("lookup enrollment token: %w", err)
	}
	return spokeID, bearerToken, true, nil
}

// RedeemEnrollmentToken atomically marks secret as redeemed, returning
// whether it actually was - the same WHERE-guarded pattern Claim uses to
// make its own single-winner guarantee atomic. ok=false covers "doesn't
// exist," "expired," and "already redeemed" alike (the caller decides how
// to present that; this doesn't distinguish which, mirroring Claim's own
// plain bool return).
func (s *Store) RedeemEnrollmentToken(secret string, now time.Time) (bool, error) {
	result, err := s.db.Exec(`
		UPDATE enrollment_tokens SET redeemed_at = ?
		WHERE secret = ? AND redeemed_at IS NULL AND expires_at > ?`,
		now, secret, now)
	if err != nil {
		return false, fmt.Errorf("redeem enrollment token: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("redeem enrollment token rows affected: %w", err)
	}
	return affected > 0, nil
}
