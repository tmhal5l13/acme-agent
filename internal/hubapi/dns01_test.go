package hubapi

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/tmhal5l13/acme-agent/config"
)

func TestDNS01Present_AuthorizedDomain(t *testing.T) {
	fake := &fakeDNSProvider{}
	s := newTestServer(t, testConfig(), map[string]challenge.Provider{"fake": fake})

	body, _ := json.Marshal(dns01Request{Domain: "example.com", Token: "tok", KeyAuth: "tok.auth"})
	resp := doRequest(s, "POST", "/v1/certs/cert-a/dns01/present", "token-a", body)

	if resp.Code != 204 {
		t.Fatalf("got status %d, want 204, body=%s", resp.Code, resp.Body.String())
	}
	if len(fake.presentCalls) != 1 {
		t.Fatalf("got %d Present calls, want 1", len(fake.presentCalls))
	}
	if got := fake.presentCalls[0]; got.Domain != "example.com" || got.Token != "tok" || got.KeyAuth != "tok.auth" {
		t.Errorf("Present called with %+v, want domain=example.com token=tok key_auth=tok.auth", got)
	}
}

func TestDNS01Present_WildcardDomainAuthorized(t *testing.T) {
	// cert-a's Domains list includes the literal string "*.example.com" —
	// this proves the authorization check matches exactly what lego sends
	// for a wildcard cert's DNS-01 challenge (domain includes the "*."
	// prefix), not some derived/stripped form of it.
	fake := &fakeDNSProvider{}
	s := newTestServer(t, testConfig(), map[string]challenge.Provider{"fake": fake})

	body, _ := json.Marshal(dns01Request{Domain: "*.example.com", Token: "tok", KeyAuth: "tok.auth"})
	resp := doRequest(s, "POST", "/v1/certs/cert-a/dns01/present", "token-a", body)

	if resp.Code != 204 {
		t.Fatalf("got status %d, want 204, body=%s", resp.Code, resp.Body.String())
	}
	if len(fake.presentCalls) != 1 {
		t.Fatalf("got %d Present calls, want 1", len(fake.presentCalls))
	}
}

// TestDomainAuthorized_NormalizesCaseAndTrailingDot proves a case or
// trailing-dot mismatch between the hub's configured domain and what a
// spoke requests doesn't spuriously reject an otherwise-correctly-
// authorized request - see domainAuthorized's doc comment for why this is
// a robustness fix (fails closed either way), not a security one.
func TestDomainAuthorized_NormalizesCaseAndTrailingDot(t *testing.T) {
	cert := config.SpokeCertConfig{Domains: []string{"example.com", "*.example.com"}}

	cases := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"EXAMPLE.COM", true},
		{"Example.Com", true},
		{"example.com.", true},
		{"EXAMPLE.COM.", true},
		{"*.example.com", true},
		{"*.EXAMPLE.COM", true},
		{"other.com", false},
		{"evil.example.com.attacker.net", false},
	}
	for _, c := range cases {
		if got := domainAuthorized(cert, c.domain); got != c.want {
			t.Errorf("domainAuthorized(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
}

// TestDNS01Present_DomainNormalization_EndToEnd is the HTTP-level version
// of the same proof, going through the real handler and a real
// challenge.Provider rather than calling domainAuthorized directly.
func TestDNS01Present_DomainNormalization_EndToEnd(t *testing.T) {
	fake := &fakeDNSProvider{}
	s := newTestServer(t, testConfig(), map[string]challenge.Provider{"fake": fake})

	body, _ := json.Marshal(dns01Request{Domain: "EXAMPLE.COM.", Token: "tok", KeyAuth: "tok.auth"})
	resp := doRequest(s, "POST", "/v1/certs/cert-a/dns01/present", "token-a", body)

	if resp.Code != 204 {
		t.Fatalf("got status %d, want 204, body=%s", resp.Code, resp.Body.String())
	}
}

func TestDNS01Present_UnauthorizedDomainRejected(t *testing.T) {
	fake := &fakeDNSProvider{}
	s := newTestServer(t, testConfig(), map[string]challenge.Provider{"fake": fake})

	body, _ := json.Marshal(dns01Request{Domain: "evil.example.net", Token: "tok", KeyAuth: "tok.auth"})
	resp := doRequest(s, "POST", "/v1/certs/cert-a/dns01/present", "token-a", body)

	if resp.Code != 403 {
		t.Fatalf("got status %d, want 403, body=%s", resp.Code, resp.Body.String())
	}
	if len(fake.presentCalls) != 0 {
		t.Fatalf("got %d Present calls for an unauthorized domain, want 0 — the DNS provider must never be touched", len(fake.presentCalls))
	}
}

func TestDNS01Cleanup_AuthorizedDomain(t *testing.T) {
	fake := &fakeDNSProvider{}
	s := newTestServer(t, testConfig(), map[string]challenge.Provider{"fake": fake})

	body, _ := json.Marshal(dns01Request{Domain: "example.com", Token: "tok", KeyAuth: "tok.auth"})
	resp := doRequest(s, "POST", "/v1/certs/cert-a/dns01/cleanup", "token-a", body)

	if resp.Code != 204 {
		t.Fatalf("got status %d, want 204, body=%s", resp.Code, resp.Body.String())
	}
	if len(fake.cleanupCalls) != 1 {
		t.Fatalf("got %d CleanUp calls, want 1", len(fake.cleanupCalls))
	}
}

func TestDNS01Present_ProviderErrorReturns502(t *testing.T) {
	fake := &fakeDNSProvider{presentErr: errors.New("route53 api unavailable")}
	s := newTestServer(t, testConfig(), map[string]challenge.Provider{"fake": fake})

	body, _ := json.Marshal(dns01Request{Domain: "example.com", Token: "tok", KeyAuth: "tok.auth"})
	resp := doRequest(s, "POST", "/v1/certs/cert-a/dns01/present", "token-a", body)

	if resp.Code != 502 {
		t.Fatalf("got status %d, want 502", resp.Code)
	}
}

// blockingDNSProvider's Present never returns on its own - only used to
// prove withTimeout actually stops the handler from waiting forever.
type blockingDNSProvider struct{}

func (blockingDNSProvider) Present(domain, token, keyAuth string) error {
	select {} // block forever
}
func (blockingDNSProvider) CleanUp(domain, token, keyAuth string) error { return nil }

// TestDNS01Present_ProviderTimeoutReturnsError proves the handler returns
// once DNSProviderTimeout elapses rather than hanging - the actual point
// of withTimeout, not just that a slow provider eventually errors somehow.
func TestDNS01Present_ProviderTimeoutReturnsError(t *testing.T) {
	cfg := testConfig()
	cfg.DNSProviderTimeout = config.Duration(10 * time.Millisecond)
	s := newTestServer(t, cfg, map[string]challenge.Provider{"fake": blockingDNSProvider{}})

	body, _ := json.Marshal(dns01Request{Domain: "example.com", Token: "tok", KeyAuth: "tok.auth"})

	done := make(chan *httptestRecorderResult, 1)
	go func() {
		resp := doRequest(s, "POST", "/v1/certs/cert-a/dns01/present", "token-a", body)
		done <- &httptestRecorderResult{code: resp.Code, body: resp.Body.String()}
	}()

	select {
	case result := <-done:
		if result.code != 502 {
			t.Errorf("got status %d, want 502 (dns provider request failed)", result.code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return within 2s of a 10ms provider timeout - withTimeout did not stop it from blocking")
	}
}

type httptestRecorderResult struct {
	code int
	body string
}

func TestDNS01Present_UnknownCertNameRejectedBeforeReachingProvider(t *testing.T) {
	// Belt-and-suspenders on the auth boundary itself: a request for a
	// cert name this spoke doesn't own must never reach the DNS provider,
	// regardless of what domain is in the body.
	fake := &fakeDNSProvider{}
	s := newTestServer(t, testConfig(), map[string]challenge.Provider{"fake": fake})

	body, _ := json.Marshal(dns01Request{Domain: "example.com", Token: "tok", KeyAuth: "tok.auth"})
	resp := doRequest(s, "POST", "/v1/certs/not-my-cert/dns01/present", "token-a", body)

	if resp.Code != 403 {
		t.Fatalf("got status %d, want 403", resp.Code)
	}
	if len(fake.presentCalls) != 0 {
		t.Fatalf("got %d Present calls, want 0", len(fake.presentCalls))
	}
}
