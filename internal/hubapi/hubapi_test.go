package hubapi

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"acme-agent/config"
	"acme-agent/internal/hubstore"
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
// the given config and DNS providers.
func newTestServer(t *testing.T, cfg *config.HubConfig, providers map[string]challenge.Provider) *Server {
	t.Helper()

	st, err := hubstore.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	tokenToSpoke := make(map[string]string, len(cfg.Spokes))
	for spokeID, spoke := range cfg.Spokes {
		tokenToSpoke[spoke.Token] = spokeID
	}

	return &Server{cfg: cfg, store: st, tokenToSpoke: tokenToSpoke, dnsProviders: providers}
}

// testConfig is one spoke ("spoke-a", token "token-a") authorized for one
// certificate ("cert-a", domains example.com + *.example.com, provider
// "fake"). Individual tests copy and adjust fields (e.g. per-cert
// RenewBefore) where they need different behavior.
func testConfig() *config.HubConfig {
	return &config.HubConfig{
		ACMEDefaults: config.ACMEDefaultsConfig{RenewBefore: config.Duration(30 * 24 * time.Hour)},
		Spokes: map[string]config.SpokeEntry{
			"spoke-a": {
				Token: "token-a",
				Certs: []config.SpokeCertConfig{
					{Name: "cert-a", Domains: []string{"example.com", "*.example.com"}, DNSProvider: "fake"},
				},
			},
		},
	}
}
