package hubapi

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
)

// fakeDNSProvider records every Present/CleanUp call it receives instead of
// touching a real DNS API, so dns01 tests can run fast and offline while
// still exercising the real HTTP handlers end to end.
type fakeDNSProvider struct {
	presentCalls []dns01Request
	cleanupCalls []dns01Request
	presentErr   error
	cleanupErr   error
}

func (f *fakeDNSProvider) Present(domain, token, keyAuth string) error {
	f.presentCalls = append(f.presentCalls, dns01Request{Domain: domain, Token: token, KeyAuth: keyAuth})
	return f.presentErr
}

func (f *fakeDNSProvider) CleanUp(domain, token, keyAuth string) error {
	f.cleanupCalls = append(f.cleanupCalls, dns01Request{Domain: domain, Token: token, KeyAuth: keyAuth})
	return f.cleanupErr
}

// newTestServer builds a real Server backed by a temp-file SQLite store
// (cheap, and exercises the real hubstore rather than a mock of it) with
// the given config, spokes, and DNS providers.
//
// hubState is built directly here rather than via buildState (which
// would read spokes/dns_providers from the store and try to construct
// real challenge.Provider values for the latter) - tests pass fakes
// directly instead (see fakeDNSProvider), so the state's spokes/
// dnsProviders maps are exactly what the caller gave them, decoupled
// from whatever (if anything) the test has separately written into the
// store itself. Tests specifically exercising the store-backed path
// (e.g. reload_test.go's Reload calls) go through buildState/Reload for
// real instead - see those tests for the difference.
func newTestServer(t *testing.T, cfg *config.HubConfig, spokes map[string]config.SpokeEntry, providers map[string]challenge.Provider) *Server {
	t.Helper()

	st, err := hubstore.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	tokenToSpoke := make(map[string]string, len(spokes))
	for spokeID, spoke := range spokes {
		for _, token := range spoke.Tokens {
			tokenToSpoke[token] = spokeID
		}
	}

	s := &Server{store: st}
	s.state.Store(&hubState{cfg: cfg, spokes: spokes, tokenToSpoke: tokenToSpoke, dnsProviders: providers})
	return s
}

// testConfig is cfg's startup-only fields, unrelated to any particular
// spoke. Individual tests copy and adjust fields (e.g. per-cert
// RenewBefore, via testSpokes) where they need different behavior.
func testConfig() *config.HubConfig {
	return &config.HubConfig{
		ACMEDefaults:         config.ACMEDefaultsConfig{RenewBefore: config.Duration(30 * 24 * time.Hour)},
		DNSProviderTimeout:   config.Duration(3 * time.Minute),
		WatchdogStaleAfter:   config.Duration(2 * time.Hour),
		RenewalLeaseDuration: config.Duration(15 * time.Minute),
	}
}

// seedSpokes writes every spoke, its tokens, and its certs directly into
// st - unlike newTestServer's default bypass (which injects hubState
// directly, decoupled from the store), this is for tests that call
// s.Reload for real, since buildState reads desired state from the store,
// not from anything passed to newTestServer. A stub DNS provider (a real,
// buildable Type - "route53" - regardless of what name the test's certs
// actually reference) is created for every distinct DNSProvider/
// DomainDNSProviders value referenced, so both UpsertSpokeCert's
// existence check and a real Reload's buildState succeed; no test using
// this helper cares about the provider's real identity, only that
// something buildable exists under the referenced name.
func seedSpokes(t *testing.T, st *hubstore.Store, spokes map[string]config.SpokeEntry) {
	t.Helper()

	providerNames := make(map[string]bool)
	for _, spoke := range spokes {
		for _, cert := range spoke.Certs {
			providerNames[cert.DNSProvider] = true
			for _, p := range cert.DomainDNSProviders {
				providerNames[p] = true
			}
		}
	}
	for name := range providerNames {
		if err := st.UpsertDNSProvider(name, config.DNSProviderConfig{Type: "route53"}); err != nil {
			t.Fatalf("seedSpokes: upsert dns provider %q: %v", name, err)
		}
	}

	for spokeID, spoke := range spokes {
		if len(spoke.Tokens) == 0 {
			t.Fatalf("seedSpokes: spoke %q has no tokens", spokeID)
		}
		if err := st.CreateSpoke(spokeID, spoke.Tokens[0]); err != nil {
			t.Fatalf("seedSpokes: create spoke %q: %v", spokeID, err)
		}
		for _, token := range spoke.Tokens[1:] {
			if err := st.AddSpokeToken(spokeID, token); err != nil {
				t.Fatalf("seedSpokes: add token to spoke %q: %v", spokeID, err)
			}
		}
		for _, cert := range spoke.Certs {
			if err := st.UpsertSpokeCert(spokeID, cert); err != nil {
				t.Fatalf("seedSpokes: upsert cert for spoke %q: %v", spokeID, err)
			}
		}
	}
}

// testSpokes is one spoke ("spoke-a", token "token-a") authorized for one
// certificate ("cert-a", domains example.com + *.example.com, provider
// "fake") - the desired-state half of what testConfig used to carry
// directly on HubConfig, before spokes moved to the database.
func testSpokes() map[string]config.SpokeEntry {
	return map[string]config.SpokeEntry{
		"spoke-a": {
			Tokens: []string{"token-a"},
			Certs: []config.SpokeCertConfig{
				{Name: "cert-a", Domains: []string{"example.com", "*.example.com"}, DNSProvider: "fake"},
			},
		},
	}
}
