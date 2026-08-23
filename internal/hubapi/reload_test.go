package hubapi

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
)

// TestReload_InvalidConfigLeavesOldStateServing proves a bad new state
// (here, a stored dns_providers entry with an unbuildable type - the
// database can hold this today, since hubstore.UpsertDNSProvider doesn't
// validate Type against internal/dnsprovider's known set - see its own
// doc comment) is rejected outright, and the server keeps serving exactly
// what it was serving before the attempted reload - never a half-applied
// state.
func TestReload_InvalidConfigLeavesOldStateServing(t *testing.T) {
	cfg := testConfig()
	s := newTestServer(t, cfg, testSpokes(), map[string]challenge.Provider{"fake": &fakeDNSProvider{}})

	// Sanity: works before the bad reload.
	resp := doRequest(s, "GET", "/v1/certs/cert-a/due", "token-a", nil)
	if resp.Code != 200 {
		t.Fatalf("got status %d before Reload, want 200", resp.Code)
	}

	if err := s.store.UpsertDNSProvider("broken", config.DNSProviderConfig{Type: "not-a-real-provider-type"}); err != nil {
		t.Fatalf("seed broken dns provider: %v", err)
	}
	if err := s.Reload(cfg); err == nil {
		t.Fatal("expected Reload to reject a store holding an unbuildable dns provider, got nil error")
	}

	// The old state must still be serving - same token, same cert, still works.
	resp = doRequest(s, "GET", "/v1/certs/cert-a/due", "token-a", nil)
	if resp.Code != 200 {
		t.Errorf("got status %d after a rejected Reload, want 200 (old state should still be serving)", resp.Code)
	}
}

// TestReload_NewSpokeAuthorizesWithoutRestart is the actual point of this
// feature: a spoke added to the database authorizes on its very next
// request after a Reload, with no process restart.
func TestReload_NewSpokeAuthorizesWithoutRestart(t *testing.T) {
	cfg := testConfig()
	s := newTestServer(t, cfg, testSpokes(), map[string]challenge.Provider{"fake": &fakeDNSProvider{}})

	// spoke-b doesn't exist yet.
	resp := doRequest(s, "GET", "/v1/certs/cert-b/due", "token-b", nil)
	if resp.Code != 401 {
		t.Fatalf("got status %d for a not-yet-configured spoke, want 401", resp.Code)
	}

	// Reload rebuilds state entirely from the store (see buildState), so
	// spoke-a needs to genuinely be there too - not just injected directly
	// into the initial hubState the way newTestServer's bypass does - or
	// it would stop authorizing the moment Reload runs. See seedSpokes.
	spokes := testSpokes()
	spokes["spoke-b"] = config.SpokeEntry{
		Tokens: []string{"token-b"},
		Certs: []config.SpokeCertConfig{
			{Name: "cert-b", Domains: []string{"other.example.com"}, DNSProvider: "fake"},
		},
	}
	seedSpokes(t, s.store, spokes)
	if err := s.Reload(cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resp = doRequest(s, "GET", "/v1/certs/cert-b/due", "token-b", nil)
	if resp.Code != 200 {
		t.Errorf("got status %d for spoke-b immediately after Reload, want 200 (no restart should be needed)", resp.Code)
	}

	// spoke-a must still work too - a reload adding a spoke shouldn't
	// disturb anyone else's.
	resp = doRequest(s, "GET", "/v1/certs/cert-a/due", "token-a", nil)
	if resp.Code != 200 {
		t.Errorf("got status %d for spoke-a after an unrelated Reload, want 200", resp.Code)
	}
}

// TestReload_ConcurrentRequestsDuringReload is the -race bar: real reader
// goroutines hammering authorize (via handleDue) while the main goroutine
// runs a bounded series of real store writes + Reload calls, proving
// atomic.Pointer actually rules out torn reads across a desired state
// that's genuinely changing underneath concurrent readers, not just that
// it compiles. Every request against spoke-a (untouched by the churn)
// must complete cleanly with 200 - never a panic, never a nil-map access.
func TestReload_ConcurrentRequestsDuringReload(t *testing.T) {
	cfg := testConfig()
	spokes := testSpokes()
	s := newTestServer(t, cfg, spokes, map[string]challenge.Provider{"fake": &fakeDNSProvider{}})
	seedSpokes(t, s.store, spokes) // spoke-a, so Reload's store-sourced rebuild still finds it
	if err := s.store.CreateSpoke("spoke-b", "token-b"); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	certB := config.SpokeCertConfig{Name: "cert-b", Domains: []string{"other.example.com"}, DNSProvider: "fake"}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	const readers = 8
	wg.Add(readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// token-a is valid regardless of spoke-b's churn - every
				// one of these must succeed no matter what's happening to
				// spoke-b at the moment it runs.
				resp := doRequest(s, "GET", "/v1/certs/cert-a/due", "token-a", nil)
				if resp.Code != 200 {
					t.Errorf("got status %d for spoke-a mid-reload-churn, want 200", resp.Code)
				}
			}
		}()
	}

	// A bounded number of real store writes + Reload cycles, spaced out
	// rather than looping as fast as a single goroutine can manage -
	// churning the store thousands of times a second isn't a realistic
	// reload cadence (real reloads happen on a SIGHUP or one admin
	// action) and only starves the 8 readers' own writes (handleDue's
	// Claim call) of SQLite's single-writer slot for no proof this test
	// actually needs. Toggles spoke-b's one certificate in and out, so
	// desired state genuinely changes shape between reloads, not just a
	// no-op rebuild from identical data.
	toggle := false
	for i := 0; i < 10; i++ {
		var err error
		if toggle {
			err = s.store.UpsertSpokeCert("spoke-b", certB)
		} else {
			err = s.store.RemoveSpokeCert("spoke-b", "cert-b")
		}
		if err != nil && !errors.Is(err, hubstore.ErrNotFound) {
			t.Errorf("toggle spoke-b cert: %v", err)
		}
		toggle = !toggle
		if err := s.Reload(cfg); err != nil {
			t.Errorf("Reload: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	close(stop)
	wg.Wait()
}
