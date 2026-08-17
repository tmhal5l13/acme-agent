package hubapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tmhal5l13/acme-agent/config"
)

// notifyTestConfig is testConfig with a notify_hook that appends
// "$ACME_STATUS $ACME_PREVIOUS_STATUS" to marker, one line per firing —
// so a test can assert exactly how many times (and with what values) the
// hook actually ran.
func notifyTestConfig(marker string) *config.HubConfig {
	cfg := testConfig()
	cfg.NotifyHook = `echo "$ACME_STATUS $ACME_PREVIOUS_STATUS" >> ` + marker
	cfg.NotifyTimeout = config.Duration(2 * time.Second)
	return cfg
}

func checkin(t *testing.T, s *Server, status string) {
	t.Helper()
	body, _ := json.Marshal(checkinRequest{
		Domains: []string{"example.com"}, NotAfter: time.Now().Add(60 * 24 * time.Hour), Status: status,
	})
	resp := doRequest(s, "POST", "/v1/certs/cert-a/checkin", "token-a", body)
	if resp.Code != 204 {
		t.Fatalf("checkin(%s): got status %d, want 204, body=%s", status, resp.Code, resp.Body.String())
	}
}

func readMarkerLines(t *testing.T, marker string) []string {
	t.Helper()
	data, err := os.ReadFile(marker)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func TestNotify_FirstCheckinActiveDoesNotFire(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	s := newTestServer(t, notifyTestConfig(marker), nil)

	checkin(t, s, "active") // unknown -> active: not a failure transition

	if got := readMarkerLines(t, marker); len(got) != 0 {
		t.Errorf("got %d notify firings for unknown->active, want 0: %v", len(got), got)
	}
}

func TestNotify_FirstCheckinFailedFires(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	s := newTestServer(t, notifyTestConfig(marker), nil)

	checkin(t, s, "failed") // unknown -> failed: alert-worthy even with no prior success

	got := readMarkerLines(t, marker)
	if len(got) != 1 {
		t.Fatalf("got %d notify firings for unknown->failed, want 1: %v", len(got), got)
	}
	if want := "failed unknown"; got[0] != want {
		t.Errorf("got %q, want %q", got[0], want)
	}
}

func TestNotify_ActiveToFailedFires(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	s := newTestServer(t, notifyTestConfig(marker), nil)

	checkin(t, s, "active")
	checkin(t, s, "failed")

	got := readMarkerLines(t, marker)
	if len(got) != 1 {
		t.Fatalf("got %d notify firings, want 1 (only for the active->failed transition): %v", len(got), got)
	}
	if want := "failed active"; got[0] != want {
		t.Errorf("got %q, want %q", got[0], want)
	}
}

func TestNotify_RepeatedFailureDoesNotRefire(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	s := newTestServer(t, notifyTestConfig(marker), nil)

	checkin(t, s, "active")
	checkin(t, s, "failed") // fires: active -> failed
	checkin(t, s, "failed") // must NOT refire: failed -> failed
	checkin(t, s, "failed") // must NOT refire: failed -> failed

	got := readMarkerLines(t, marker)
	if len(got) != 1 {
		t.Fatalf("got %d notify firings across 3 consecutive failed checkins, want 1 (no spam on repeats): %v", len(got), got)
	}
}

func TestNotify_RecoveryFires(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	s := newTestServer(t, notifyTestConfig(marker), nil)

	checkin(t, s, "active")
	checkin(t, s, "failed")
	checkin(t, s, "active") // recovery: failed -> active

	got := readMarkerLines(t, marker)
	if len(got) != 2 {
		t.Fatalf("got %d notify firings, want 2 (alert + recovery): %v", len(got), got)
	}
	if want := "active failed"; got[1] != want {
		t.Errorf("got %q for the recovery firing, want %q", got[1], want)
	}
}

func TestNotify_DisabledByEmptyHook(t *testing.T) {
	cfg := testConfig() // NotifyHook left empty
	s := newTestServer(t, cfg, nil)

	checkin(t, s, "active")
	checkin(t, s, "failed")
	// No marker file was ever configured, so there's nothing to read - the
	// only assertion is that checkin() above didn't fail or hang despite
	// NotifyHook being empty.
}
