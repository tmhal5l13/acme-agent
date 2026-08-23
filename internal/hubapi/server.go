// Package hubapi implements the hub's HTTP API: the endpoints spokes poll
// for renewal instructions, report their certificate state to, and relay
// DNS-01 challenges through.
package hubapi

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/dnsprovider"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
)

// hubState is every piece of desired-state a request handler reads,
// bundled into one struct so a config reload (see Reload) always swaps
// all three together — a handler that loads this once at the top of a
// request can never observe tokenToSpoke from a newer reload paired with
// cfg from an older one, or vice versa, the torn-state bug this bundling
// exists to rule out by construction.
type hubState struct {
	cfg          *config.HubConfig
	tokenToSpoke map[string]string
	dnsProviders map[string]challenge.Provider
}

// Server holds everything request handlers need: the hub's desired-state
// (behind state, reloadable — see Reload) and its observed-state store
// (never reloaded; hubstore.Store manages its own connection for the
// process lifetime).
type Server struct {
	state atomic.Pointer[hubState]
	store *hubstore.Store
}

// buildState builds a hubState from cfg: its token->spoke index and one
// challenge.Provider per named entry in config's dns_providers. Building
// every configured DNS provider up front means a bad provider config
// (e.g. an unknown type) is caught here — at startup, or at Reload time —
// not on the first request that happens to need it.
func buildState(cfg *config.HubConfig) (*hubState, error) {
	tokenToSpoke := make(map[string]string, len(cfg.Spokes))
	for spokeID, spoke := range cfg.Spokes {
		// One entry per token, all pointing at the same spoke - this is
		// what lets both an old and new token authenticate during a
		// rotation grace period (see config.SpokeEntry.Tokens).
		for _, token := range spoke.Tokens {
			tokenToSpoke[token] = spokeID
		}
	}

	dnsProviders := make(map[string]challenge.Provider, len(cfg.DNSProviders))
	for name, providerCfg := range cfg.DNSProviders {
		provider, err := dnsprovider.New(providerCfg)
		if err != nil {
			return nil, fmt.Errorf("build dns provider %q: %w", name, err)
		}
		dnsProviders[name] = provider
	}

	return &hubState{
		cfg:          cfg,
		tokenToSpoke: tokenToSpoke,
		dnsProviders: dnsProviders,
	}, nil
}

// NewServer builds a Server from cfg and store — see buildState for what
// "building" means.
func NewServer(cfg *config.HubConfig, store *hubstore.Store) (*Server, error) {
	state, err := buildState(cfg)
	if err != nil {
		return nil, err
	}

	s := &Server{store: store}
	s.state.Store(state)
	return s, nil
}

// Reload rebuilds hubState from cfg and swaps it in atomically — see
// ARCHITECTURE.md "Config hot-reload" for exactly what's reloadable this
// way (spokes, dns_providers) versus what still needs a real restart
// (listen_addr, TLS cert paths, data_dir, db_path — resources already
// bound at process start, which no handler here ever reads anyway).
//
// On error, the prior state is left serving untouched — a bad new config
// (e.g. a cert now referencing an unknown dns_provider) must never
// partially apply.
func (s *Server) Reload(cfg *config.HubConfig) error {
	state, err := buildState(cfg)
	if err != nil {
		return err
	}
	s.state.Store(state)
	return nil
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
	// Checked once here, not through state.Load() - StatusToken is
	// deliberately not part of the hot-reloadable field set (see "Config
	// hot-reload" in ARCHITECTURE.md), so this matches every other
	// startup-only setting.
	if s.state.Load().cfg.StatusToken != "" {
		mux.HandleFunc("GET /v1/status", s.handleStatus)
	}
	return mux
}
