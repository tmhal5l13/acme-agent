package hubapi

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-acme/lego/v4/challenge"
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
