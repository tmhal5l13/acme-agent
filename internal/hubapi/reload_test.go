package hubapi

import (
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/tmhal5l13/acme-agent/config"
)

// TestReload_InvalidConfigLeavesOldStateServing proves a bad new config
// (here, a cert referencing an undefined dns_provider entry - the same
// shape config.HubConfig.validate() would normally catch before this ever
// reaches Reload, but Reload can't assume its caller always validates
// first) is rejected outright, and the server keeps serving exactly what
// it was serving before the attempted reload - never a half-applied state.
func TestReload_InvalidConfigLeavesOldStateServing(t *testing.T) {
	s := newTestServer(t, testConfig(), map[string]challenge.Provider{"fake": &fakeDNSProvider{}})

	// Sanity: works before the bad reload.
	resp := doRequest(s, "GET", "/v1/certs/cert-a/due", "token-a", nil)
	if resp.Code != 200 {
		t.Fatalf("got status %d before Reload, want 200", resp.Code)
	}

	badCfg := testConfig()
	badCfg.DNSProviders = map[string]config.DNSProviderConfig{
		"broken": {Type: "not-a-real-provider-type"},
	}
	if err := s.Reload(badCfg); err == nil {
		t.Fatal("expected Reload to reject a config with an unbuildable dns provider, got nil error")
	}

	// The old state must still be serving - same token, same cert, still works.
	resp = doRequest(s, "GET", "/v1/certs/cert-a/due", "token-a", nil)
	if resp.Code != 200 {
		t.Errorf("got status %d after a rejected Reload, want 200 (old state should still be serving)", resp.Code)
	}
}

// TestReload_NewSpokeAuthorizesWithoutRestart is the actual point of this
// feature: a spoke added via Reload authorizes on its very next request,
// with no process restart - the failure mode this whole PR exists to fix
// (today, this requires restarting the hub, see the "No hot-reload" known
// gap this PR removes).
func TestReload_NewSpokeAuthorizesWithoutRestart(t *testing.T) {
	s := newTestServer(t, testConfig(), map[string]challenge.Provider{"fake": &fakeDNSProvider{}})

	// spoke-b doesn't exist yet.
	resp := doRequest(s, "GET", "/v1/certs/cert-b/due", "token-b", nil)
	if resp.Code != 401 {
		t.Fatalf("got status %d for a not-yet-configured spoke, want 401", resp.Code)
	}

	cfg := testConfig()
	cfg.Spokes["spoke-b"] = config.SpokeEntry{
		Tokens: []string{"token-b"},
		Certs: []config.SpokeCertConfig{
			{Name: "cert-b", Domains: []string{"other.example.com"}, DNSProvider: "fake"},
		},
	}
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

// TestReload_ConcurrentRequestsDuringReload is the -race bar: real
// goroutines hammering authorize (via handleDue) while another goroutine
// calls Reload in a loop, proving atomic.Pointer actually rules out torn
// reads rather than just compiling. Every request must complete cleanly
// (200 or a normal auth failure) - never a panic, never a nil-map access.
func TestReload_ConcurrentRequestsDuringReload(t *testing.T) {
	s := newTestServer(t, testConfig(), map[string]challenge.Provider{"fake": &fakeDNSProvider{}})

	cfgA := testConfig()
	cfgB := testConfig()
	cfgB.Spokes["spoke-b"] = config.SpokeEntry{
		Tokens: []string{"token-b"},
		Certs: []config.SpokeCertConfig{
			{Name: "cert-b", Domains: []string{"other.example.com"}, DNSProvider: "fake"},
		},
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		toggle := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			cfg := cfgA
			if toggle {
				cfg = cfgB
			}
			toggle = !toggle
			if err := s.Reload(cfg); err != nil {
				t.Errorf("Reload: %v", err)
			}
		}
	}()

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
				// token-a is valid under both cfgA and cfgB - every one
				// of these must succeed regardless of which config is
				// live at the moment it runs.
				resp := doRequest(s, "GET", "/v1/certs/cert-a/due", "token-a", nil)
				if resp.Code != 200 {
					t.Errorf("got status %d for spoke-a mid-reload-churn, want 200", resp.Code)
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}
