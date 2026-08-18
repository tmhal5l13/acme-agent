package hubapi

// TestPebble_HubRelay_FullIssuance drives the complete spoke<->hub<->CA
// pipeline with zero fakes anywhere in the chain: a real hubclient.Client
// talks over real TLS to a real hubapi.Server, which relays real DNS-01
// challenges to a real ACME server (pebble). This is the counterpart to
// internal/acmeclient's pebble_test.go, which proves the ACME-facing half
// works; this proves the hub's relay handlers (handleDNS01Present/Cleanup)
// actually work end to end too, not just that they compile against a fake
// challenge.Provider (see fakeDNSProvider in hubapi_test.go, used by every
// other dns01 test in this package).
//
// Gated the same way as internal/acmeclient's pebble tests: skipped, not
// failed, unless ACME_AGENT_E2E_TESTS is set and pebble/pebble-challtestsrv
// are on $PATH.
//
// This package's pebble instance binds the same fixed ports internal/acmeclient's
// does. If enabling ACME_AGENT_E2E_TESTS for both packages in one `go test`
// invocation, pass `-p 1` to avoid them colliding - see the longer note in
// internal/acmeclient/pebble_test.go.

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/acmeclient"
	"github.com/tmhal5l13/acme-agent/internal/hubclient"
	"github.com/tmhal5l13/acme-agent/internal/selfsigned"
	"github.com/tmhal5l13/acme-agent/internal/store"
)

func TestPebble_HubRelay_FullIssuance(t *testing.T) {
	requirePebbleE2E(t)
	startChallTestSrv(t)
	pebbleCACertFile := startPebble(t)

	// Real hub: a real Server, holding a real challTestSrvProvider under
	// the "pebble" dns_provider name - from the spoke's perspective this
	// is indistinguishable from a hub relaying to a real DNS API, which is
	// exactly the point.
	cfg := testConfig()
	cfg.Spokes["spoke-a"].Certs[0].DNSProvider = "pebble"
	s := newTestServer(t, cfg, map[string]challenge.Provider{"pebble": challTestSrvProvider{}})

	hubCertPath := filepath.Join(t.TempDir(), "hub-cert.pem")
	hubKeyPath := filepath.Join(t.TempDir(), "hub-key.pem")
	if err := selfsigned.EnsureCert(hubCertPath, hubKeyPath, "127.0.0.1"); err != nil {
		t.Fatalf("generate hub cert: %v", err)
	}

	addr, shutdown := startHubTLSServer(t, s, hubCertPath, hubKeyPath)
	defer shutdown()

	hub, err := hubclient.New("https://"+addr, "token-a", hubCertPath)
	if err != nil {
		t.Fatalf("hubclient.New: %v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "spoke.db"))
	if err != nil {
		t.Fatalf("open spoke store: %v", err)
	}
	defer st.Close()

	acmeCfg := config.ACMEConfig{
		DirectoryURL: pebbleDirectoryURL,
		CACertFile:   pebbleCACertFile,
		Email:        "test@example.com",
	}

	user, err := acmeclient.GetOrRegisterAccount(st, pebbleDirectoryURL, acmeCfg)
	if err != nil {
		t.Fatalf("GetOrRegisterAccount: %v", err)
	}

	provider := &hubclient.DNS01Provider{Client: hub, CertName: "cert-a", Timeout: 30 * time.Second}

	cert, err := acmeclient.Issue(user, pebbleDirectoryURL, acmeCfg, provider,
		[]string{"example.com"}, dns01.DisableCompletePropagationRequirement())
	if err != nil {
		t.Fatalf("Issue via hub relay: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("Issue returned no certificate bytes")
	}
}

// TestPebble_ClaimPreventsDuplicateIssuance is the real payoff of PR 1's
// Pebble infrastructure landing before this one: it proves the renewal
// lease actually prevents a duplicate concurrent renewal against real
// ACME machinery, not just that hubstore.Claim's SQL is atomic in
// isolation (see internal/hubstore's own TestClaim_ConcurrentCallersOnlyOneSucceeds
// for that narrower proof). Two goroutines simulate two processes of what's
// supposed to be one spoke - the actual scenario this feature exists for,
// e.g. a botched restart leaving an old instance still running - both
// racing to claim and, if they win, drive a real issuance through the hub
// relay to Pebble. Exactly one must get due=true, and exactly one must
// actually reach Pebble's ACME API and succeed.
func TestPebble_ClaimPreventsDuplicateIssuance(t *testing.T) {
	requirePebbleE2E(t)
	startChallTestSrv(t)
	pebbleCACertFile := startPebble(t)

	cfg := testConfig()
	cfg.Spokes["spoke-a"].Certs[0].DNSProvider = "pebble"
	cfg.RenewalLeaseDuration = config.Duration(time.Minute) // comfortably longer than this test takes
	s := newTestServer(t, cfg, map[string]challenge.Provider{"pebble": challTestSrvProvider{}})

	hubCertPath := filepath.Join(t.TempDir(), "hub-cert.pem")
	hubKeyPath := filepath.Join(t.TempDir(), "hub-key.pem")
	if err := selfsigned.EnsureCert(hubCertPath, hubKeyPath, "127.0.0.1"); err != nil {
		t.Fatalf("generate hub cert: %v", err)
	}
	addr, shutdown := startHubTLSServer(t, s, hubCertPath, hubKeyPath)
	defer shutdown()

	acmeCfg := config.ACMEConfig{
		DirectoryURL: pebbleDirectoryURL,
		CACertFile:   pebbleCACertFile,
		Email:        "test@example.com",
	}

	const attempts = 2
	var wg sync.WaitGroup
	dueResults := make(chan bool, attempts)
	issued := make(chan bool, attempts)

	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		i := i
		go func() {
			defer wg.Done()

			hub, err := hubclient.New("https://"+addr, "token-a", hubCertPath)
			if err != nil {
				t.Errorf("attempt %d: hubclient.New: %v", i, err)
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			due, err := hub.Due(ctx, "cert-a")
			if err != nil {
				t.Errorf("attempt %d: Due: %v", i, err)
				return
			}
			dueResults <- due
			if !due {
				return // lost the race - exactly the behavior under test
			}

			// Separate local store per attempt, matching what two real,
			// independent spoke processes would each have (not two
			// goroutines sharing one local database, which isn't how
			// this ever runs in production).
			st, err := store.Open(filepath.Join(t.TempDir(), fmt.Sprintf("spoke-%d.db", i)))
			if err != nil {
				t.Errorf("attempt %d: open store: %v", i, err)
				return
			}
			defer st.Close()

			user, err := acmeclient.GetOrRegisterAccount(st, pebbleDirectoryURL, acmeCfg)
			if err != nil {
				t.Errorf("attempt %d: GetOrRegisterAccount: %v", i, err)
				return
			}

			provider := &hubclient.DNS01Provider{Client: hub, CertName: "cert-a", Timeout: 30 * time.Second}
			cert, err := acmeclient.Issue(user, pebbleDirectoryURL, acmeCfg, provider,
				[]string{"example.com"}, dns01.DisableCompletePropagationRequirement())
			if err != nil {
				t.Errorf("attempt %d: Issue: %v", i, err)
				return
			}
			if cert == nil || len(cert.Certificate) == 0 {
				t.Errorf("attempt %d: Issue returned no certificate bytes", i)
				return
			}
			issued <- true
		}()
	}
	wg.Wait()
	close(dueResults)
	close(issued)

	dueTrueCount := 0
	for due := range dueResults {
		if due {
			dueTrueCount++
		}
	}
	if dueTrueCount != 1 {
		t.Errorf("got %d of %d concurrent Due() calls reporting due=true, want exactly 1", dueTrueCount, attempts)
	}

	issuedCount := 0
	for range issued {
		issuedCount++
	}
	if issuedCount != 1 {
		t.Errorf("got %d successful real issuances against Pebble, want exactly 1 — the claim should have stopped the second attempt before it ever reached the ACME API", issuedCount)
	}
}
