package hubapi

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"acme-agent/config"
)

func doRequest(s *Server, method, path, token string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	s.Handler().ServeHTTP(r, req)
	return r
}

func TestAuth_NoToken(t *testing.T) {
	s := newTestServer(t, testConfig(), nil)
	resp := doRequest(s, "GET", "/v1/certs/cert-a/due", "", nil)
	if resp.Code != 401 {
		t.Fatalf("got status %d, want 401", resp.Code)
	}
}

func TestAuth_UnknownToken(t *testing.T) {
	s := newTestServer(t, testConfig(), nil)
	resp := doRequest(s, "GET", "/v1/certs/cert-a/due", "not-a-real-token", nil)
	if resp.Code != 401 {
		t.Fatalf("got status %d, want 401", resp.Code)
	}
}

func TestAuth_ValidTokenWrongCertName(t *testing.T) {
	s := newTestServer(t, testConfig(), nil)
	resp := doRequest(s, "GET", "/v1/certs/not-my-cert/due", "token-a", nil)
	if resp.Code != 403 {
		t.Fatalf("got status %d, want 403", resp.Code)
	}
}

func TestCheckin_ValidRequestStoresState(t *testing.T) {
	s := newTestServer(t, testConfig(), nil)

	notAfter := time.Now().Add(60 * 24 * time.Hour).UTC()
	body, _ := json.Marshal(checkinRequest{
		Domains:   []string{"example.com"},
		NotBefore: time.Now().UTC(),
		NotAfter:  notAfter,
		Serial:    "abc123",
		Status:    "active",
	})

	resp := doRequest(s, "POST", "/v1/certs/cert-a/checkin", "token-a", body)
	if resp.Code != 204 {
		t.Fatalf("got status %d, want 204, body=%s", resp.Code, resp.Body.String())
	}

	state, err := s.store.Get("spoke-a", "cert-a")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if state.Status != "active" {
		t.Errorf("got status %q, want %q", state.Status, "active")
	}
	if state.SerialNumber.String != "abc123" {
		t.Errorf("got serial %q, want %q", state.SerialNumber.String, "abc123")
	}
}

func TestCheckin_InvalidBody(t *testing.T) {
	s := newTestServer(t, testConfig(), nil)
	resp := doRequest(s, "POST", "/v1/certs/cert-a/checkin", "token-a", []byte("not json"))
	if resp.Code != 400 {
		t.Fatalf("got status %d, want 400", resp.Code)
	}
}

func TestDue_NeverCheckedIn(t *testing.T) {
	s := newTestServer(t, testConfig(), nil)
	resp := doRequest(s, "GET", "/v1/certs/cert-a/due", "token-a", nil)
	if resp.Code != 200 {
		t.Fatalf("got status %d, want 200", resp.Code)
	}
	var got dueResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.Due {
		t.Error("got due=false for a cert that has never checked in, want true")
	}
}

func TestDue_FarFutureExpiryIsNotDue(t *testing.T) {
	s := newTestServer(t, testConfig(), nil)
	if err := s.store.Checkin("spoke-a", "cert-a", time.Now(), time.Now().Add(90*24*time.Hour), "s1", "active", nil); err != nil {
		t.Fatalf("seed checkin: %v", err)
	}

	resp := doRequest(s, "GET", "/v1/certs/cert-a/due", "token-a", nil)
	var got dueResponse
	json.NewDecoder(resp.Body).Decode(&got)
	if got.Due {
		t.Error("got due=true for a cert with 90 days left (default renew_before is 30 days), want false")
	}
}

func TestDue_NearExpiryIsDue(t *testing.T) {
	s := newTestServer(t, testConfig(), nil)
	if err := s.store.Checkin("spoke-a", "cert-a", time.Now(), time.Now().Add(5*24*time.Hour), "s1", "active", nil); err != nil {
		t.Fatalf("seed checkin: %v", err)
	}

	resp := doRequest(s, "GET", "/v1/certs/cert-a/due", "token-a", nil)
	var got dueResponse
	json.NewDecoder(resp.Body).Decode(&got)
	if !got.Due {
		t.Error("got due=false for a cert with 5 days left (default renew_before is 30 days), want true")
	}
}

func TestDue_PerCertRenewBeforeOverridesDefault(t *testing.T) {
	cfg := testConfig()
	// Override just this cert's renewal policy to 1 hour, far shorter than
	// the 30-day default — a cert with 5 days left should now read as NOT
	// due, proving the override actually takes effect over the default.
	spoke := cfg.Spokes["spoke-a"]
	spoke.Certs[0].RenewBefore = config.Duration(time.Hour)
	cfg.Spokes["spoke-a"] = spoke

	s := newTestServer(t, cfg, nil)
	if err := s.store.Checkin("spoke-a", "cert-a", time.Now(), time.Now().Add(5*24*time.Hour), "s1", "active", nil); err != nil {
		t.Fatalf("seed checkin: %v", err)
	}

	resp := doRequest(s, "GET", "/v1/certs/cert-a/due", "token-a", nil)
	var got dueResponse
	json.NewDecoder(resp.Body).Decode(&got)
	if got.Due {
		t.Error("got due=true with a 1h renew_before override and 5 days left, want false")
	}
}
