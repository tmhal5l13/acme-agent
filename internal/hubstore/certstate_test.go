package hubstore

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestCheckinActive_StoresFields(t *testing.T) {
	st := openTestStore(t)
	notBefore := time.Now()
	notAfter := notBefore.Add(90 * 24 * time.Hour)

	if err := st.CheckinActive("spoke-a", "cert-a", notBefore, notAfter, "serial-1"); err != nil {
		t.Fatalf("CheckinActive: %v", err)
	}

	cs, err := st.Get("spoke-a", "cert-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cs.Status != "active" {
		t.Errorf("got status %q, want %q", cs.Status, "active")
	}
	if !cs.NotAfter.Valid || !cs.NotAfter.Time.Equal(notAfter) {
		t.Errorf("got not_after %v, want %v", cs.NotAfter, notAfter)
	}
	if !cs.SerialNumber.Valid || cs.SerialNumber.String != "serial-1" {
		t.Errorf("got serial %v, want %q", cs.SerialNumber, "serial-1")
	}
	if !cs.LastSuccessAt.Valid {
		t.Error("last_success_at is not set after a successful checkin")
	}
	if cs.ConsecutiveFailures != 0 {
		t.Errorf("got consecutive_failures %d, want 0", cs.ConsecutiveFailures)
	}
}

// TestCheckinFailed_PreservesCertFields is the actual proof of the bug fix
// this split exists for: a failed renewal attempt must not make the hub
// forget the real expiry of whatever certificate the spoke still has
// installed. Before this split, CheckinFailed's predecessor unconditionally
// overwrote not_before/not_after/serial_number with the failed request's
// zero-valued fields, which would have made a still-perfectly-valid
// certificate look like it had no known expiry at all.
func TestCheckinFailed_PreservesCertFields(t *testing.T) {
	st := openTestStore(t)
	notBefore := time.Now()
	notAfter := notBefore.Add(60 * 24 * time.Hour)

	if err := st.CheckinActive("spoke-a", "cert-a", notBefore, notAfter, "serial-1"); err != nil {
		t.Fatalf("CheckinActive: %v", err)
	}

	if err := st.CheckinFailed("spoke-a", "cert-a", errors.New("dns01 present failed"), 1); err != nil {
		t.Fatalf("CheckinFailed: %v", err)
	}

	cs, err := st.Get("spoke-a", "cert-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cs.Status != "failed" {
		t.Errorf("got status %q, want %q", cs.Status, "failed")
	}
	if !cs.NotAfter.Valid || !cs.NotAfter.Time.Equal(notAfter) {
		t.Errorf("not_after changed after a failed checkin: got %v, want unchanged %v", cs.NotAfter, notAfter)
	}
	if !cs.NotBefore.Valid || !cs.NotBefore.Time.Equal(notBefore) {
		t.Errorf("not_before changed after a failed checkin: got %v, want unchanged %v", cs.NotBefore, notBefore)
	}
	if !cs.SerialNumber.Valid || cs.SerialNumber.String != "serial-1" {
		t.Errorf("serial_number changed after a failed checkin: got %v, want unchanged %q", cs.SerialNumber, "serial-1")
	}
}

func TestCheckinFailed_RecordsErrorAndFailureStreak(t *testing.T) {
	st := openTestStore(t)

	if err := st.CheckinFailed("spoke-a", "cert-a", errors.New("boom"), 3); err != nil {
		t.Fatalf("CheckinFailed: %v", err)
	}

	cs, err := st.Get("spoke-a", "cert-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !cs.LastError.Valid || cs.LastError.String != "boom" {
		t.Errorf("got last_error %v, want %q", cs.LastError, "boom")
	}
	if cs.ConsecutiveFailures != 3 {
		t.Errorf("got consecutive_failures %d, want 3", cs.ConsecutiveFailures)
	}
}

// TestCheckinFailed_DoesNotSetLastSuccessAt proves last_success_at only
// ever reflects an actual success, never a failed attempt — the whole
// point of tracking it separately from last_checkin_at.
func TestCheckinFailed_DoesNotSetLastSuccessAt(t *testing.T) {
	st := openTestStore(t)

	if err := st.CheckinFailed("spoke-a", "cert-a", errors.New("boom"), 1); err != nil {
		t.Fatalf("CheckinFailed: %v", err)
	}

	cs, err := st.Get("spoke-a", "cert-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cs.LastSuccessAt.Valid {
		t.Error("last_success_at is set after a certificate that has never once succeeded")
	}
}

// TestCheckinActive_ResetsFailureStreak proves a recovery (active after a
// run of failures) clears the streak rather than leaving stale failure
// data next to a now-healthy certificate.
func TestCheckinActive_ResetsFailureStreak(t *testing.T) {
	st := openTestStore(t)

	if err := st.CheckinFailed("spoke-a", "cert-a", errors.New("boom"), 4); err != nil {
		t.Fatalf("CheckinFailed: %v", err)
	}
	if err := st.CheckinActive("spoke-a", "cert-a", time.Now(), time.Now().Add(90*24*time.Hour), "serial-2"); err != nil {
		t.Fatalf("CheckinActive: %v", err)
	}

	cs, err := st.Get("spoke-a", "cert-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cs.Status != "active" {
		t.Errorf("got status %q, want %q", cs.Status, "active")
	}
	if cs.ConsecutiveFailures != 0 {
		t.Errorf("got consecutive_failures %d after a successful checkin, want reset to 0", cs.ConsecutiveFailures)
	}
	if cs.LastError.Valid {
		t.Errorf("got last_error %v after a successful checkin, want cleared", cs.LastError)
	}
}

func TestGet_UnknownCertReturnsErrNotFound(t *testing.T) {
	st := openTestStore(t)
	if _, err := st.Get("spoke-a", "never-checked-in"); !errors.Is(err, ErrNotFound) {
		t.Errorf("got error %v, want ErrNotFound", err)
	}
}
