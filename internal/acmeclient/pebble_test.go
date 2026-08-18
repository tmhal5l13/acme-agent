package acmeclient

// These tests exercise GetOrRegisterAccount and Issue against a real,
// local ACME server (github.com/letsencrypt/pebble) instead of mocking the
// ACME protocol - the same discipline this project has used for every
// other milestone (real DNS providers, real Let's Encrypt staging), now
// available for account registration/issuance too without needing real
// Let's Encrypt infrastructure or real DNS credentials on every run. See
// requirePebbleE2E for why this is skipped, not failed, when pebble isn't
// installed.
//
// account.go and manager.go (the actual ACME protocol calls) had zero test
// coverage before this file - only directory.go's pure unit-level URL/HTTP
// client resolution was tested.
//
// pebble and pebble-challtestsrv bind fixed ports (14000, 15000, 8053,
// 8055, ...) that aren't fully reconfigurable (pebble-challtestsrv's DoH
// listener on :8443 has no disabling flag, for example), and this
// package's tests run concurrently in a separate OS process from
// internal/hubapi's own pebble_test.go, which also launches pebble and
// pebble-challtestsrv, if `go test` is run against both with its default
// per-package parallelism. When enabling ACME_AGENT_E2E_TESTS across more
// than one of these packages in the same invocation, pass `go test -p 1`
// to force one package's test binary to run at a time.

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/store"
)

// Pebble's own DNS resolution is pointed at pebble-challtestsrv (see
// startPebble's -dnsserver flag), but lego's own client-side propagation
// pre-check - which runs before it tells the ACME server the challenge is
// ready - resolves against the real system resolver by default, which will
// never see a record only served by challtestsrv. Disabling it here is the
// exact same option internal/spokeagent/agent.go's SkipPropagationCheck
// config flag threads through in production, just always-on for this test
// rather than operator-configured.
var pebbleChallengeOpts = []dns01.ChallengeOption{dns01.DisableCompletePropagationRequirement()}

// TestPebble_IssueAndRenew proves the full GetOrRegisterAccount -> Issue
// round trip against a real ACME server: register an account, issue a
// certificate via real DNS-01 challenges relayed to pebble-challtestsrv,
// then issue again for the same domain (simulating a renewal) to confirm
// a second real order against an already-registered account also works.
func TestPebble_IssueAndRenew(t *testing.T) {
	requirePebbleE2E(t)
	startChallTestSrv(t)
	caCertFile := startPebble(t)

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	acmeCfg := config.ACMEConfig{
		DirectoryURL: pebbleDirectoryURL,
		CACertFile:   caCertFile,
		Email:        "test@example.com",
	}

	user, err := GetOrRegisterAccount(st, pebbleDirectoryURL, acmeCfg)
	if err != nil {
		t.Fatalf("GetOrRegisterAccount: %v", err)
	}
	if user.Registration == nil || user.Registration.URI == "" {
		t.Fatal("got a user with no registration URI after a successful account registration")
	}

	// A second call for the same directory URL must reuse the persisted
	// account rather than registering a new one.
	user2, err := GetOrRegisterAccount(st, pebbleDirectoryURL, acmeCfg)
	if err != nil {
		t.Fatalf("GetOrRegisterAccount (second call): %v", err)
	}
	if user2.Registration.URI != user.Registration.URI {
		t.Errorf("second GetOrRegisterAccount got a different account (URI %q) than the first (%q) - want the persisted one reused",
			user2.Registration.URI, user.Registration.URI)
	}

	const domain = "acme-agent-pebble-test.example.com"
	provider := challTestSrvProvider{}

	before := time.Now()
	cert, err := Issue(user, pebbleDirectoryURL, acmeCfg, provider, []string{domain}, pebbleChallengeOpts...)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("Issue returned no certificate bytes")
	}

	notBefore, notAfter, _, err := parseCertTimesForTest(cert.Certificate)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	if notBefore.Before(before.Add(-time.Hour)) || notBefore.After(time.Now().Add(time.Hour)) {
		t.Errorf("got not_before %s, want roughly now (%s)", notBefore, before)
	}
	if !notAfter.After(notBefore) {
		t.Errorf("got not_after %s not after not_before %s", notAfter, notBefore)
	}

	// Renewal: a second Issue call for the same domain against the same
	// account must also succeed - proves the account/order flow works
	// repeatedly, not just once from a clean state.
	renewed, err := Issue(user, pebbleDirectoryURL, acmeCfg, provider, []string{domain}, pebbleChallengeOpts...)
	if err != nil {
		t.Fatalf("Issue (renewal): %v", err)
	}
	if renewed == nil || len(renewed.Certificate) == 0 {
		t.Fatal("renewal Issue returned no certificate bytes")
	}
}

// parseCertTimesForTest mirrors internal/spokeagent's parseCertTimes
// closely enough for this test's purposes, kept local rather than
// exported from spokeagent to avoid a cross-package test-only dependency
// for three lines of x509 parsing.
func parseCertTimesForTest(certPEM []byte) (notBefore, notAfter time.Time, serial string, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, time.Time{}, "", fmt.Errorf("no PEM block found in certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, "", err
	}
	return cert.NotBefore, cert.NotAfter, cert.SerialNumber.String(), nil
}
