package hubapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/tmhal5l13/acme-agent/config"
)

type dns01Request struct {
	Domain  string `json:"domain"`
	Token   string `json:"token"`
	KeyAuth string `json:"key_auth"`
}

// maxRequestBodyBytes bounds the request body every hub API handler that
// decodes JSON will read (see handlers.go's handleCheckin too). Domain
// names, ACME tokens, key authorizations, and checkin metadata are all
// short strings - a legitimate request is well under 1KB - so this is
// generous headroom, not a tight fit, while still bounding how much an
// authenticated-but-misbehaving spoke can make the hub buffer per request.
const maxRequestBodyBytes = 64 << 10

// handleDNS01Present relays a spoke's DNS-01 Present call to the real DNS
// provider, which stays entirely hub-side — this is the one place a
// challenge token (never a credential) crosses from spoke to hub.
func (s *Server) handleDNS01Present(w http.ResponseWriter, r *http.Request) {
	s.handleDNS01(w, r, func(provider challenge.Provider, req dns01Request) error {
		return provider.Present(req.Domain, req.Token, req.KeyAuth)
	})
}

// handleDNS01Cleanup relays a spoke's DNS-01 CleanUp call the same way.
func (s *Server) handleDNS01Cleanup(w http.ResponseWriter, r *http.Request) {
	s.handleDNS01(w, r, func(provider challenge.Provider, req dns01Request) error {
		return provider.CleanUp(req.Domain, req.Token, req.KeyAuth)
	})
}

func (s *Server) handleDNS01(w http.ResponseWriter, r *http.Request, do func(challenge.Provider, dns01Request) error) {
	spokeID, cert, err := s.authorize(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var req dns01Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !domainAuthorized(cert, req.Domain) {
		slog.Warn("dns01 request for unauthorized domain", "spoke", spokeID, "cert", cert.Name, "domain", req.Domain)
		http.Error(w, fmt.Sprintf("domain %q is not authorized for cert %q", req.Domain, cert.Name), http.StatusForbidden)
		return
	}

	state := s.state.Load()

	providerName := resolveDNSProvider(cert, req.Domain)
	provider, ok := state.dnsProviders[providerName]
	if !ok {
		// Config validation at load time already guarantees every cert's
		// dns_provider (and every domain_dns_providers override) references
		// a defined entry, so this would mean a bug in that validation, not
		// a bad request.
		slog.Error("dns01 request: dns provider not found", "provider", providerName)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := withTimeout(state.cfg.DNSProviderTimeout.Duration(), func() error { return do(provider, req) }); err != nil {
		slog.Error("dns01 request failed", "spoke", spokeID, "cert", cert.Name, "domain", req.Domain, "error", err)
		http.Error(w, "dns provider request failed", http.StatusBadGateway)
		return
	}

	slog.Info("dns01 request", "spoke", spokeID, "cert", cert.Name, "domain", req.Domain, "path", r.URL.Path)
	w.WriteHeader(http.StatusNoContent)
}

// domainAuthorized reports whether domain is one cert is actually
// configured to cover. This is what stops a spoke — even an authenticated,
// otherwise-legitimate one — from requesting a DNS-01 change for a domain
// it wasn't granted, by supplying an unexpected value in the request body
// rather than the path.
//
// Comparison is case-insensitive with a trailing dot ignored on either
// side. This is a robustness fix, not a security one: without it, the
// match is exact-string, which fails *closed* on a mismatch (a spoke
// requesting "Example.com" against a config listing "example.com" gets
// rejected, never let through) - normalizing just stops an operator's
// harmless capitalization or trailing-dot difference between the hub's
// and spoke's config from breaking an otherwise-correctly-authorized
// renewal.
func domainAuthorized(cert config.SpokeCertConfig, domain string) bool {
	want := normalizeDomain(domain)
	for _, d := range cert.Domains {
		if normalizeDomain(d) == want {
			return true
		}
	}
	return false
}

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(d, "."))
}

// resolveDNSProvider returns which dns_providers entry should handle
// domain for cert: its entry in DomainDNSProviders if one exists, else
// cert's own DNSProvider default — see SpokeCertConfig.DomainDNSProviders'
// doc comment for why a single cert's domains can span more than one DNS
// provider at all. Matched with the same case/trailing-dot normalization
// domainAuthorized uses, for the same reason: a spoke's request and the
// hub's own config shouldn't have to agree on formatting exactly for an
// otherwise-correct match to work.
func resolveDNSProvider(cert config.SpokeCertConfig, domain string) string {
	want := normalizeDomain(domain)
	for d, provider := range cert.DomainDNSProviders {
		if normalizeDomain(d) == want {
			return provider
		}
	}
	return cert.DNSProvider
}

// withTimeout runs fn, returning its error if it completes within
// timeout. lego's challenge.Provider interface (Present/CleanUp) takes no
// context.Context, and no context-aware variant exists in the pinned
// lego version, so there's no way to pass a deadline into fn itself - the
// only option is to run it in its own goroutine and stop waiting on it,
// not to actually cancel it. That distinction matters: on timeout, fn
// keeps running to completion (or failure) against the real DNS provider
// in the background: this only stops the HTTP handler — and the spoke
// waiting on it — from blocking indefinitely.
func withTimeout(timeout time.Duration, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("dns provider call timed out after %s", timeout)
	}
}
