package hubapi

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/tmhal5l13/acme-agent/config"
)

func doEnroll(s *Server, secret string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(enrollRequest{Secret: secret})
	r := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body))
	s.Handler().ServeHTTP(r, req)
	return r
}

func TestHandleEnroll_ValidSecretForConfiguredSpokeSucceeds(t *testing.T) {
	s := newTestServer(t, testConfig(), testSpokes(), map[string]challenge.Provider{"fake": &fakeDNSProvider{}})
	if err := s.store.InsertEnrollmentToken("secret-a", "spoke-a", "token-a", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	resp := doEnroll(s, "secret-a")
	if resp.Code != 200 {
		t.Fatalf("got status %d, want 200, body=%s", resp.Code, resp.Body.String())
	}

	var got enrollResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.SpokeID != "spoke-a" || got.BearerToken != "token-a" {
		t.Errorf("got spoke_id=%q bearer_token=%q, want spoke-a/token-a", got.SpokeID, got.BearerToken)
	}
	if len(got.Certs) != 1 || got.Certs[0].Name != "cert-a" {
		t.Fatalf("got certs %+v, want one entry named cert-a", got.Certs)
	}
	if len(got.Certs[0].Domains) != 2 || got.Certs[0].Domains[0] != "example.com" {
		t.Errorf("got domains %v, want [example.com *.example.com]", got.Certs[0].Domains)
	}
}

func TestHandleEnroll_UnknownSecretRejected(t *testing.T) {
	s := newTestServer(t, testConfig(), testSpokes(), map[string]challenge.Provider{"fake": &fakeDNSProvider{}})
	resp := doEnroll(s, "no-such-secret")
	if resp.Code != 401 {
		t.Fatalf("got status %d, want 401", resp.Code)
	}
}

func TestHandleEnroll_ExpiredSecretRejected(t *testing.T) {
	s := newTestServer(t, testConfig(), testSpokes(), map[string]challenge.Provider{"fake": &fakeDNSProvider{}})
	if err := s.store.InsertEnrollmentToken("secret-a", "spoke-a", "token-a", time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	resp := doEnroll(s, "secret-a")
	if resp.Code != 401 {
		t.Fatalf("got status %d, want 401", resp.Code)
	}
}

func TestHandleEnroll_AlreadyRedeemedSecretRejected(t *testing.T) {
	s := newTestServer(t, testConfig(), testSpokes(), map[string]challenge.Provider{"fake": &fakeDNSProvider{}})
	if err := s.store.InsertEnrollmentToken("secret-a", "spoke-a", "token-a", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	if resp := doEnroll(s, "secret-a"); resp.Code != 200 {
		t.Fatalf("first enroll: got status %d, want 200, body=%s", resp.Code, resp.Body.String())
	}

	resp := doEnroll(s, "secret-a")
	if resp.Code != 401 {
		t.Fatalf("second enroll with the same secret: got status %d, want 401", resp.Code)
	}
}

func TestHandleEnroll_InvalidBodyRejected(t *testing.T) {
	s := newTestServer(t, testConfig(), testSpokes(), map[string]challenge.Provider{"fake": &fakeDNSProvider{}})
	r := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader([]byte("not json")))
	s.Handler().ServeHTTP(r, req)
	if r.Code != 400 {
		t.Fatalf("got status %d for a malformed body, want 400", r.Code)
	}
}

func TestHandleEnroll_EmptySecretRejected(t *testing.T) {
	s := newTestServer(t, testConfig(), testSpokes(), map[string]challenge.Provider{"fake": &fakeDNSProvider{}})
	resp := doEnroll(s, "")
	if resp.Code != 400 {
		t.Fatalf("got status %d for an empty secret, want 400", resp.Code)
	}
}

// TestHandleEnroll_SpokeNotYetConfiguredDoesNotConsumeSecret is the most
// important test in this file: proves the specific ordering handleEnroll
// depends on for correctness (see its doc comment) - a secret whose spoke
// isn't in the hub's live desired state yet gets a 503 without being
// burned, and the exact same secret succeeds once the spoke is created
// and the hub reloads (via Server.Reload, which - since the PR3 cutover -
// rebuilds state from the database, not a restart).
func TestHandleEnroll_SpokeNotYetConfiguredDoesNotConsumeSecret(t *testing.T) {
	cfg := testConfig()
	s := newTestServer(t, cfg, testSpokes(), map[string]challenge.Provider{"fake": &fakeDNSProvider{}})
	if err := s.store.InsertEnrollmentToken("secret-new", "spoke-new", "token-new", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	resp := doEnroll(s, "secret-new")
	if resp.Code != 503 {
		t.Fatalf("got status %d before spoke-new exists, want 503, body=%s", resp.Code, resp.Body.String())
	}

	// Reload rebuilds state entirely from the store (see buildState), so
	// the new spoke's cert needs a real, store-registered dns_provider -
	// "fake" (only ever injected directly into the initial hubState by
	// newTestServer, bypassing the store) won't survive a real reload.
	if err := s.store.UpsertDNSProvider("route53", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}
	if err := s.store.CreateSpoke("spoke-new", "token-new"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := s.store.UpsertSpokeCert("spoke-new", config.SpokeCertConfig{
		Name: "cert-new", Domains: []string{"new.example.com"}, DNSProvider: "route53",
	}); err != nil {
		t.Fatalf("UpsertSpokeCert: %v", err)
	}
	if err := s.Reload(cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resp = doEnroll(s, "secret-new")
	if resp.Code != 200 {
		t.Fatalf("got status %d for the same secret after reload, want 200 (the 503 must not have consumed it), body=%s", resp.Code, resp.Body.String())
	}

	var got enrollResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.SpokeID != "spoke-new" || len(got.Certs) != 1 || got.Certs[0].Name != "cert-new" {
		t.Errorf("got %+v, want spoke-new with one cert named cert-new", got)
	}
}
