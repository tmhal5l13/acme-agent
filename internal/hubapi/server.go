// Package hubapi implements the hub's HTTP API: the endpoints spokes poll
// for renewal instructions, report their certificate state to, and relay
// DNS-01 challenges through.
package hubapi

import (
	"fmt"
	"net/http"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/dnsprovider"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
)

// Server holds everything request handlers need: the hub's desired-state
// config, its observed-state store, a token->spoke index, and one
// challenge.Provider per named entry in config's dns_providers — all built
// once at startup rather than reconstructed per request.
type Server struct {
	cfg          *config.HubConfig
	store        *hubstore.Store
	tokenToSpoke map[string]string
	dnsProviders map[string]challenge.Provider
}

// NewServer builds a Server, its token index, and its DNS providers from
// cfg. Building every configured DNS provider up front means a bad
// provider config (e.g. an unknown type) is caught at startup, not on the
// first request that happens to need it.
func NewServer(cfg *config.HubConfig, store *hubstore.Store) (*Server, error) {
	tokenToSpoke := make(map[string]string, len(cfg.Spokes))
	for spokeID, spoke := range cfg.Spokes {
		tokenToSpoke[spoke.Token] = spokeID
	}

	dnsProviders := make(map[string]challenge.Provider, len(cfg.DNSProviders))
	for name, providerCfg := range cfg.DNSProviders {
		provider, err := dnsprovider.New(providerCfg)
		if err != nil {
			return nil, fmt.Errorf("build dns provider %q: %w", name, err)
		}
		dnsProviders[name] = provider
	}

	return &Server{
		cfg:          cfg,
		store:        store,
		tokenToSpoke: tokenToSpoke,
		dnsProviders: dnsProviders,
	}, nil
}

// Handler returns the routed HTTP handler for the hub's API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/certs/{name}/checkin", s.handleCheckin)
	mux.HandleFunc("GET /v1/certs/{name}/due", s.handleDue)
	mux.HandleFunc("POST /v1/certs/{name}/dns01/present", s.handleDNS01Present)
	mux.HandleFunc("POST /v1/certs/{name}/dns01/cleanup", s.handleDNS01Cleanup)
	// /v1/status only exists at all when status_token is configured - see
	// HubConfig.StatusToken's doc comment. Registering it unconditionally
	// and rejecting every request when the token is empty would work too,
	// but not existing is a clearer signal than a route that 401s forever.
	if s.cfg.StatusToken != "" {
		mux.HandleFunc("GET /v1/status", s.handleStatus)
	}
	return mux
}
