package hubapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/tmhal5l13/acme-agent/config"
)

type dns01Request struct {
	Domain  string `json:"domain"`
	Token   string `json:"token"`
	KeyAuth string `json:"key_auth"`
}

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

	provider, ok := s.dnsProviders[cert.DNSProvider]
	if !ok {
		// Config validation at load time already guarantees every cert's
		// dns_provider references a defined entry, so this would mean a
		// bug in that validation, not a bad request.
		slog.Error("dns01 request: dns provider not found", "provider", cert.DNSProvider)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := do(provider, req); err != nil {
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
func domainAuthorized(cert config.SpokeCertConfig, domain string) bool {
	return slices.Contains(cert.Domains, domain)
}
