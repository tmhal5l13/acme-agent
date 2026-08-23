package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/hubapi"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
)

func parseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block found in cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// TestEnsureTLS_WildcardListenAddrWithoutTLSHostProducesUselessSAN documents
// the failure mode TLSHost exists to fix: a wildcard listen_addr with no
// override embeds "0.0.0.0" as the certificate's SAN, which cannot match
// any real address a spoke dials — every spoke's TLS handshake would fail
// (see ARCHITECTURE.md's "TLS" section). This isn't the desired behavior,
// just today's default when TLSHost is left unset for a wildcard bind.
func TestEnsureTLS_WildcardListenAddrWithoutTLSHostProducesUselessSAN(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.HubConfig{
		ListenAddr:  "0.0.0.0:8443",
		TLSCertFile: filepath.Join(dir, "cert.pem"),
		TLSKeyFile:  filepath.Join(dir, "key.pem"),
	}

	if err := ensureTLS(cfg); err != nil {
		t.Fatalf("ensureTLS: %v", err)
	}

	cert := parseCert(t, cfg.TLSCertFile)
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "0.0.0.0" {
		t.Fatalf("got IP SANs %v, want exactly [0.0.0.0] — this test exists to catch anything that accidentally makes this useless SAN correct instead of overridable", cert.IPAddresses)
	}
}

// TestEnsureTLS_TLSHostOverridesWildcardListenAddr is the actual fix: with
// TLSHost set, the certificate's SAN is the real address spokes dial, not
// the meaningless "0.0.0.0" a wildcard listen_addr would otherwise produce.
func TestEnsureTLS_TLSHostOverridesWildcardListenAddr(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.HubConfig{
		ListenAddr:  "0.0.0.0:8443",
		TLSHost:     "hub.example.com",
		TLSCertFile: filepath.Join(dir, "cert.pem"),
		TLSKeyFile:  filepath.Join(dir, "key.pem"),
	}

	if err := ensureTLS(cfg); err != nil {
		t.Fatalf("ensureTLS: %v", err)
	}

	cert := parseCert(t, cfg.TLSCertFile)
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "hub.example.com" {
		t.Errorf("got DNSNames %v, want exactly [hub.example.com]", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 0 {
		t.Errorf("got IP SANs %v, want none — hub.example.com is a hostname, not an IP", cert.IPAddresses)
	}
}

// TestEnsureTLS_TLSHostUnsetFallsBackToListenAddr preserves the original
// behavior for the common case: a specific, dialable listen_addr (not a
// wildcard) with no TLSHost override still gets the right SAN from
// listen_addr alone, same as before TLSHost existed.
func TestEnsureTLS_TLSHostUnsetFallsBackToListenAddr(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.HubConfig{
		ListenAddr:  "192.0.2.10:8443",
		TLSCertFile: filepath.Join(dir, "cert.pem"),
		TLSKeyFile:  filepath.Join(dir, "key.pem"),
	}

	if err := ensureTLS(cfg); err != nil {
		t.Fatalf("ensureTLS: %v", err)
	}

	cert := parseCert(t, cfg.TLSCertFile)
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "192.0.2.10" {
		t.Errorf("got IP SANs %v, want exactly [192.0.2.10]", cert.IPAddresses)
	}
}

const hubConfigV1 = `
listen_addr: "127.0.0.1:8443"
data_dir: /var/lib/acme-hub
dns_providers:
  route53_main:
    type: route53
spokes:
  spoke-a:
    tokens:
      - token-a
    certs:
      - name: cert-a
        domains: [example.com]
        dns_provider: route53_main
`

const hubConfigV2 = hubConfigV1 + `
  spoke-b:
    tokens:
      - token-b
    certs:
      - name: cert-b
        domains: [other.example.com]
        dns_provider: route53_main
`

// TestWatchForReload_PicksUpSIGHUP is the real-signal proof behind this
// PR's whole point: rewrite the config file a running hub is watching,
// send it a real SIGHUP (not a simulated call to Reload directly - this
// is specifically testing that the signal plumbing itself works), and
// confirm the change takes effect without restarting the process.
func TestWatchForReload_PicksUpSIGHUP(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(hubConfigV1), 0o644); err != nil {
		t.Fatalf("write initial config: %v", err)
	}

	cfg, err := config.LoadHubConfig(configPath)
	if err != nil {
		t.Fatalf("load initial config: %v", err)
	}

	st, err := hubstore.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	server, err := hubapi.NewServer(cfg, st)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Registered synchronously, here, before watchForReload runs as a
	// goroutine - see run's comment in main.go on why this ordering
	// matters: SIGHUP's default disposition terminates the process, and
	// registering inside the goroutine would leave a real window where a
	// SIGHUP arriving before signal.Notify actually runs kills the test
	// binary outright instead of being caught (this is exactly what broke
	// under load before this fix - "signal: hangup" killing the whole
	// package's test run, not just this subtest).
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	go watchForReload(ctx, sighup, configPath, server)

	// spoke-b doesn't exist in hubConfigV1 yet.
	req := httptest.NewRequest("GET", "/v1/certs/cert-b/due", nil)
	req.Header.Set("Authorization", "Bearer token-b")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("got status %d for spoke-b before reload, want 401", rec.Code)
	}

	if err := os.WriteFile(configPath, []byte(hubConfigV2), 0o644); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}

	// watchForReload's goroutine needs a moment to receive the signal and
	// finish reloading - poll rather than a single fixed sleep, so this
	// isn't flaky under load but also doesn't wait longer than it has to.
	deadline := time.Now().Add(2 * time.Second)
	for {
		req := httptest.NewRequest("GET", "/v1/certs/cert-b/due", nil)
		req.Header.Set("Authorization", "Bearer token-b")
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("spoke-b still not authorized 2s after SIGHUP, last status %d", rec.Code)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
