package hubapi

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/tmhal5l13/acme-agent/config"
)

// statusTestConfig is testConfig with a status_token set.
func statusTestConfig() *config.HubConfig {
	cfg := testConfig()
	cfg.StatusToken = "status-token"
	return cfg
}

// statusTestSpokes is testSpokes plus a second spoke/cert, so status
// tests can prove the endpoint is genuinely fleet-wide (spans spokes),
// not just "whatever a single spoke's own token would already see" - see
// HubConfig.StatusToken's doc comment on why that's the actual point of
// a separate credential.
func statusTestSpokes() map[string]config.SpokeEntry {
	spokes := testSpokes()
	spokes["spoke-b"] = config.SpokeEntry{
		Tokens: []string{"token-b"},
		Certs: []config.SpokeCertConfig{
			{Name: "cert-b", Domains: []string{"other.example.com"}, DNSProvider: "fake"},
		},
	}
	return spokes
}

func TestHandleStatus_RequiresStatusToken(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)

	resp := doRequest(s, "GET", "/v1/status", "", nil)
	if resp.Code != 401 {
		t.Errorf("no token: got status %d, want 401", resp.Code)
	}

	resp = doRequest(s, "GET", "/v1/status", "token-a", nil) // a real spoke token, but not the status token
	if resp.Code != 401 {
		t.Errorf("spoke token: got status %d, want 401 — a per-spoke token must not also work here", resp.Code)
	}

	resp = doRequest(s, "GET", "/v1/status", "status-token", nil)
	if resp.Code != 200 {
		t.Errorf("correct status token: got status %d, want 200", resp.Code)
	}
}

// TestHandleStatus_NotRegisteredWithoutStatusToken proves the route
// genuinely doesn't exist (404) rather than existing and always
// rejecting, when status_token is left unset.
func TestHandleStatus_NotRegisteredWithoutStatusToken(t *testing.T) {
	cfg := testConfig() // StatusToken deliberately left empty
	s := newTestServer(t, cfg, testSpokes(), nil)

	resp := doRequest(s, "GET", "/v1/status", "anything", nil)
	if resp.Code != 404 {
		t.Errorf("got status %d, want 404 when status_token is unset", resp.Code)
	}
}

func TestHandleStatus_ReturnsAllConfiguredCerts(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)

	notAfter := time.Now().Add(60 * 24 * time.Hour)
	if err := s.store.CheckinActive("spoke-a", "cert-a", time.Now(), notAfter, "serial-a"); err != nil {
		t.Fatalf("seed checkin: %v", err)
	}
	// spoke-b/cert-b is deliberately never checked in.

	resp := doRequest(s, "GET", "/v1/status", "status-token", nil)
	if resp.Code != 200 {
		t.Fatalf("got status %d, want 200, body=%s", resp.Code, resp.Body.String())
	}

	var entries []statusEntry
	if err := json.Unmarshal(resp.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (one per configured cert across both spokes)", len(entries))
	}

	byKey := make(map[string]statusEntry, len(entries))
	for _, e := range entries {
		byKey[e.SpokeID+"/"+e.Name] = e
	}

	a, ok := byKey["spoke-a/cert-a"]
	if !ok {
		t.Fatal("missing spoke-a/cert-a")
	}
	if a.Status != "active" || a.Serial != "serial-a" {
		t.Errorf("spoke-a/cert-a: got status=%q serial=%q, want active/serial-a", a.Status, a.Serial)
	}

	b, ok := byKey["spoke-b/cert-b"]
	if !ok {
		t.Fatal("missing spoke-b/cert-b — a configured-but-never-checked-in cert must still appear")
	}
	if b.Status != "unknown" {
		t.Errorf("spoke-b/cert-b: got status %q, want %q for a cert that's never checked in", b.Status, "unknown")
	}
}

func TestHandleStatus_ReflectsFailureStreak(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)

	if err := s.store.CheckinFailed("spoke-a", "cert-a", nil, 4); err != nil {
		t.Fatalf("seed failed checkin: %v", err)
	}

	resp := doRequest(s, "GET", "/v1/status", "status-token", nil)
	var entries []statusEntry
	if err := json.Unmarshal(resp.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	var found bool
	for _, e := range entries {
		if e.SpokeID == "spoke-a" && e.Name == "cert-a" {
			found = true
			if e.ConsecutiveFailures != 4 {
				t.Errorf("got consecutive_failures %d, want 4", e.ConsecutiveFailures)
			}
			if e.Status != "failed" {
				t.Errorf("got status %q, want failed", e.Status)
			}
		}
	}
	if !found {
		t.Fatal("spoke-a/cert-a missing from response")
	}
}
