package hubapi

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// doBasicAuthRequest mirrors doRequest (handlers_test.go), but for the
// admin dashboard's HTTP Basic Auth instead of a spoke's bearer token.
func doBasicAuthRequest(s *Server, method, path, password string) *httptest.ResponseRecorder {
	r := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	if password != "" {
		req.SetBasicAuth("admin", password) // username arbitrary/ignored - see StatusToken's doc comment
	}
	s.Handler().ServeHTTP(r, req)
	return r
}

func TestHandleAdminDashboard_RequiresStatusToken(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)

	resp := doBasicAuthRequest(s, "GET", "/admin", "")
	if resp.Code != 401 {
		t.Errorf("no credentials: got status %d, want 401", resp.Code)
	}
	if got := resp.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Basic") {
		t.Errorf("no credentials: WWW-Authenticate = %q, want it to contain %q so a browser shows its native login prompt", got, "Basic")
	}

	resp = doBasicAuthRequest(s, "GET", "/admin", "token-a") // a real spoke token, but not the status token
	if resp.Code != 401 {
		t.Errorf("spoke token as password: got status %d, want 401 — a per-spoke token must not also work here", resp.Code)
	}
	if got := resp.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Basic") {
		t.Errorf("spoke token as password: WWW-Authenticate = %q, want it to contain %q", got, "Basic")
	}

	resp = doBasicAuthRequest(s, "GET", "/admin", "status-token")
	if resp.Code != 200 {
		t.Errorf("correct status token: got status %d, want 200, body=%s", resp.Code, resp.Body.String())
	}
}

// TestHandleAdminDashboard_NotRegisteredWithoutStatusToken proves the
// route genuinely doesn't exist (404) rather than existing and always
// rejecting, when status_token is left unset — mirrors
// TestHandleStatus_NotRegisteredWithoutStatusToken exactly.
func TestHandleAdminDashboard_NotRegisteredWithoutStatusToken(t *testing.T) {
	cfg := testConfig() // StatusToken deliberately left empty
	s := newTestServer(t, cfg, statusTestSpokes(), nil)

	resp := doBasicAuthRequest(s, "GET", "/admin", "anything")
	if resp.Code != 404 {
		t.Errorf("got status %d, want 404 when status_token is unset", resp.Code)
	}
}

func TestHandleAdminDashboard_ContentTypeIsHTML(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)

	resp := doBasicAuthRequest(s, "GET", "/admin", "status-token")
	if resp.Code != 200 {
		t.Fatalf("got status %d, want 200, body=%s", resp.Code, resp.Body.String())
	}
	if ct := resp.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want a text/html prefix", ct)
	}
}

// TestHandleAdminDashboard_ShowsConfiguredButNeverCheckedInCert mirrors
// TestHandleStatus_ReturnsAllConfiguredCerts: a cert that's configured but
// has never checked in must still render, as "unknown" — not silently
// missing from the page — proving handleAdminDashboard genuinely shares
// adminEntries's behavior, not just its name.
func TestHandleAdminDashboard_ShowsConfiguredButNeverCheckedInCert(t *testing.T) {
	cfg := statusTestConfig()
	s := newTestServer(t, cfg, statusTestSpokes(), nil)

	notAfter := time.Now().Add(60 * 24 * time.Hour)
	if err := s.store.CheckinActive("spoke-a", "cert-a", time.Now(), notAfter, "serial-a"); err != nil {
		t.Fatalf("seed checkin: %v", err)
	}
	// spoke-b/cert-b is deliberately never checked in.

	resp := doBasicAuthRequest(s, "GET", "/admin", "status-token")
	if resp.Code != 200 {
		t.Fatalf("got status %d, want 200, body=%s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()

	if !strings.Contains(body, "spoke-a") || !strings.Contains(body, "cert-a") {
		t.Errorf("body missing spoke-a/cert-a:\n%s", body)
	}
	if !strings.Contains(body, "spoke-b") || !strings.Contains(body, "cert-b") {
		t.Errorf("body missing spoke-b/cert-b — a configured-but-never-checked-in cert must still appear:\n%s", body)
	}
	if !strings.Contains(body, "status-unknown") {
		t.Errorf("body missing the \"unknown\" status row class for the never-checked-in cert:\n%s", body)
	}
}

// TestHandleAdminDashboard_EscapesUntrustedFields proves html/template
// (not text/template) is actually in effect: a spoke-reported error
// containing HTML must render escaped, not as live markup.
func TestHandleAdminDashboard_EscapesUntrustedFields(t *testing.T) {
	cfg := statusTestConfig()
	s := newTestServer(t, cfg, statusTestSpokes(), nil)

	if err := s.store.CheckinFailed("spoke-a", "cert-a", errors.New("<script>alert(1)</script>"), 1); err != nil {
		t.Fatalf("seed checkin: %v", err)
	}

	resp := doBasicAuthRequest(s, "GET", "/admin", "status-token")
	if resp.Code != 200 {
		t.Fatalf("got status %d, want 200, body=%s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()

	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("body contains an unescaped <script> tag from a spoke-reported error - html/template should have escaped it:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("body missing the expected escaped form of the spoke-reported error:\n%s", body)
	}
}
