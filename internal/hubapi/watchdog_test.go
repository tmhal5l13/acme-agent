package hubapi

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tmhal5l13/acme-agent/config"
)

// watchdogTestConfig is notifyTestConfig with a very short
// WatchdogStaleAfter, so a real checkin's real last_checkin_at (always
// set to time.Now() by CheckinActive - there's no way to seed an
// artificially old one through the public API, nor should there be)
// becomes stale after a few milliseconds' real sleep rather than needing
// to wait out the 2h production default.
func watchdogTestConfig(marker string) *config.HubConfig {
	cfg := notifyTestConfig(marker)
	cfg.WatchdogStaleAfter = config.Duration(200 * time.Millisecond)
	return cfg
}

func TestWatchdog_FlagsStaleCheckin(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	s := newTestServer(t, watchdogTestConfig(marker), nil)

	if err := s.store.CheckinActive("spoke-a", "cert-a", time.Now(), time.Now().Add(90*24*time.Hour), "s1"); err != nil {
		t.Fatalf("seed checkin: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	newWatchdogState().watchdogPass(context.Background(), s)

	got := readMarkerLines(t, marker)
	if len(got) != 1 {
		t.Fatalf("got %d notify firings, want 1: %v", len(got), got)
	}
	if want := "stale unknown"; got[0] != want {
		t.Errorf("got %q, want %q", got[0], want)
	}
}

func TestWatchdog_DoesNotRenotifyEveryPass(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	s := newTestServer(t, watchdogTestConfig(marker), nil)

	if err := s.store.CheckinActive("spoke-a", "cert-a", time.Now(), time.Now().Add(90*24*time.Hour), "s1"); err != nil {
		t.Fatalf("seed checkin: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	state := newWatchdogState()
	state.watchdogPass(context.Background(), s) // fires: still fresh -> stale
	state.watchdogPass(context.Background(), s) // must not refire: still stale
	state.watchdogPass(context.Background(), s) // must not refire: still stale

	got := readMarkerLines(t, marker)
	if len(got) != 1 {
		t.Fatalf("got %d notify firings across 3 passes of the same still-stale cert, want 1 (no spam on repeats): %v", len(got), got)
	}
}

func TestWatchdog_RecoversWhenCheckinArrives(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	s := newTestServer(t, watchdogTestConfig(marker), nil)

	if err := s.store.CheckinActive("spoke-a", "cert-a", time.Now(), time.Now().Add(90*24*time.Hour), "s1"); err != nil {
		t.Fatalf("seed checkin: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	state := newWatchdogState()
	state.watchdogPass(context.Background(), s) // fires: stale

	if err := s.store.CheckinActive("spoke-a", "cert-a", time.Now(), time.Now().Add(90*24*time.Hour), "s2"); err != nil {
		t.Fatalf("fresh checkin: %v", err)
	}
	state.watchdogPass(context.Background(), s) // fires: recovered

	got := readMarkerLines(t, marker)
	if len(got) != 2 {
		t.Fatalf("got %d notify firings, want 2 (stale + recovered): %v", len(got), got)
	}
	if want := "active stale"; got[1] != want {
		t.Errorf("got %q for the recovery firing, want %q", got[1], want)
	}
}

// TestWatchdog_NeverCheckedInGetsAGracePeriod proves a certificate that's
// just been added to config (no checkin yet, the normal state right
// after onboarding a new spoke) isn't flagged on the very first pass that
// happens to see it - only after it's stayed in that state longer than
// WatchdogStaleAfter, the same margin a cert with a real checkin history
// gets naturally.
func TestWatchdog_NeverCheckedInGetsAGracePeriod(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	s := newTestServer(t, watchdogTestConfig(marker), nil)
	// Deliberately no checkin at all.

	state := newWatchdogState()
	state.watchdogPass(context.Background(), s) // first ever observation: must not fire yet

	if got := readMarkerLines(t, marker); len(got) != 0 {
		t.Fatalf("got %d notify firings on the first pass a never-checked-in cert is seen, want 0: %v", len(got), got)
	}

	time.Sleep(500 * time.Millisecond)
	state.watchdogPass(context.Background(), s) // past the grace period now

	got := readMarkerLines(t, marker)
	if len(got) != 1 {
		t.Fatalf("got %d notify firings after the grace period elapsed, want 1: %v", len(got), got)
	}
}

func TestWatchdog_FreshCheckinNeverFlagged(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	cfg := notifyTestConfig(marker) // production-realistic 2h WatchdogStaleAfter, not the test override
	s := newTestServer(t, cfg, nil)

	if err := s.store.CheckinActive("spoke-a", "cert-a", time.Now(), time.Now().Add(90*24*time.Hour), "s1"); err != nil {
		t.Fatalf("seed checkin: %v", err)
	}

	newWatchdogState().watchdogPass(context.Background(), s)

	if got := readMarkerLines(t, marker); len(got) != 0 {
		t.Fatalf("got %d notify firings for a cert that just checked in, want 0: %v", len(got), got)
	}
}
