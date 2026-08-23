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
// bundled into one struct so a reload (see Reload) always swaps all of
// it together — a handler that loads this once at the top of a request
// can never observe tokenToSpoke from a newer reload paired with spokes
// from an older one, or vice versa, the torn-state bug this bundling
// exists to rule out by construction. cfg itself no longer changes across
// a reload (spokes/dns_providers moved to the database — see buildState),
// but is still carried here for handlers that read its other,
// startup-only fields (ACMEDefaults, DNSProviderTimeout, etc.).
type hubState struct {
	cfg          *config.HubConfig
	spokes       map[string]config.SpokeEntry
	tokenToSpoke map[string]string
	dnsProviders map[string]challenge.Provider
}

// Server holds everything request handlers need: the hub's desired-state
// (behind state, reloadable — see Reload) and its observed-state store
// (never reloaded; hubstore.Store manages its own connection for the
// process lifetime — and, since PR3, is also where reload itself reads
// desired state from).
type Server struct {
	state atomic.Pointer[hubState]
	store *hubstore.Store
}

// buildState builds a hubState by reading every spoke and DNS provider
// from store: cfg's fields no longer include them (see HubConfig's doc
// comment). Building every configured DNS provider up front means a bad
// provider config (e.g. an unknown type) is caught here — at startup, or
// at Reload time — not on the first request that happens to need it.
func buildState(cfg *config.HubConfig, store *hubstore.Store) (*hubState, error) {
	spokesList, err := store.AllSpokes()
	if err != nil {
		return nil, fmt.Errorf("load spokes: %w", err)
	}
	spokes := make(map[string]config.SpokeEntry, len(spokesList))
	tokenToSpoke := make(map[string]string, len(spokesList))
	for _, spoke := range spokesList {
		spokes[spoke.ID] = config.SpokeEntry{Tokens: spoke.Tokens, Certs: spoke.Certs}
		// One entry per token, all pointing at the same spoke - this is
		// what lets both an old and new token authenticate during a
		// rotation grace period (see config.SpokeEntry.Tokens).
		for _, token := range spoke.Tokens {
			tokenToSpoke[token] = spoke.ID
		}
	}

	providerCfgs, err := store.AllDNSProviders()
	if err != nil {
		return nil, fmt.Errorf("load dns providers: %w", err)
	}
	dnsProviders := make(map[string]challenge.Provider, len(providerCfgs))
	for name, providerCfg := range providerCfgs {
		provider, err := dnsprovider.New(providerCfg)
		if err != nil {
			return nil, fmt.Errorf("build dns provider %q: %w", name, err)
		}
		dnsProviders[name] = provider
	}

	return &hubState{
		cfg:          cfg,
		spokes:       spokes,
		tokenToSpoke: tokenToSpoke,
		dnsProviders: dnsProviders,
	}, nil
}

// NewServer builds a Server from cfg and store — see buildState for what
// "building" means.
func NewServer(cfg *config.HubConfig, store *hubstore.Store) (*Server, error) {
	state, err := buildState(cfg, store)
	if err != nil {
		return nil, err
	}

	s := &Server{store: store}
	s.state.Store(state)
	return s, nil
}

// Reload rebuilds hubState from the database and swaps it in atomically —
// see ARCHITECTURE.md "Config hot-reload" for the two kinds of writer
// that call this: the web admin UI's own handlers, in-process,
// immediately after their own database write; and cmd/acme-hub's SIGHUP
// handler, for changes written by a separate CLI process (cmd/acme-onboard,
// acme-hub --generate-token) that the running hub has no other way to
// notice. cfg is still passed in (and stored on the resulting hubState)
// for its other, startup-only fields — nothing about *which* spokes/DNS
// providers exist depends on it anymore.
//
// On error, the prior state is left serving untouched — a bad DNS
// provider config (e.g. an unknown type) must never partially apply.
func (s *Server) Reload(cfg *config.HubConfig) error {
	state, err := buildState(cfg, s.store)
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
	// Registered unconditionally, unlike /v1/status below - unlike a
	// bearer token or the status token, an enrollment secret is minted
	// per-spoke on demand (see cmd/acme-hub --generate-token), so there's
	// no config setting that turns this endpoint on or off.
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
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
		mux.HandleFunc("GET /admin", s.handleAdminDashboard)
	}
	return mux
}
