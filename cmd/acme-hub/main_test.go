package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/enrolltoken"
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
`

// TestWatchForReload_PicksUpSIGHUP is the real-signal proof behind the
// original hot-reload PR's whole point: write a new spoke directly into
// the database a running hub is backed by (config.yaml itself no longer
// changes - desired state lives in hubstore now, see PR3's cutover), send
// a real SIGHUP (not a simulated call to Reload directly - this is
// specifically testing that the signal plumbing itself works), and
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

	if err := st.UpsertDNSProvider("route53_main", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("seed dns provider: %v", err)
	}
	if err := st.CreateSpoke("spoke-a", "token-a"); err != nil {
		t.Fatalf("seed spoke-a: %v", err)
	}
	if err := st.UpsertSpokeCert("spoke-a", config.SpokeCertConfig{
		Name: "cert-a", Domains: []string{"example.com"}, DNSProvider: "route53_main",
	}); err != nil {
		t.Fatalf("seed cert-a: %v", err)
	}

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

	if err := st.CreateSpoke("spoke-b", "token-b"); err != nil {
		t.Fatalf("create spoke-b: %v", err)
	}
	if err := st.UpsertSpokeCert("spoke-b", config.SpokeCertConfig{
		Name: "cert-b", Domains: []string{"other.example.com"}, DNSProvider: "route53_main",
	}); err != nil {
		t.Fatalf("create cert-b: %v", err)
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

func TestParseDomainDNSProviders_Empty(t *testing.T) {
	m, err := parseDomainDNSProviders("")
	if err != nil {
		t.Fatalf("parseDomainDNSProviders: %v", err)
	}
	if m != nil {
		t.Errorf("got %v, want nil for an empty string", m)
	}
}

func TestParseDomainDNSProviders_ParsesMultiplePairs(t *testing.T) {
	m, err := parseDomainDNSProviders("a.example.com=cloudflare_main,b.example.com=route53_main")
	if err != nil {
		t.Fatalf("parseDomainDNSProviders: %v", err)
	}
	want := map[string]string{"a.example.com": "cloudflare_main", "b.example.com": "route53_main"}
	if len(m) != len(want) {
		t.Fatalf("got %v, want %v", m, want)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("got %s=%q, want %q", k, m[k], v)
		}
	}
}

func TestParseDomainDNSProviders_RejectsMalformedPair(t *testing.T) {
	if _, err := parseDomainDNSProviders("not-a-valid-pair"); err == nil {
		t.Fatal("expected an error for a pair with no '=', got nil")
	}
}

func TestDefaultHubURL_UsesListenAddrWhenNoTLSHost(t *testing.T) {
	cfg := &config.HubConfig{ListenAddr: "192.0.2.10:8443"}
	got, err := defaultHubURL(cfg)
	if err != nil {
		t.Fatalf("defaultHubURL: %v", err)
	}
	if got != "https://192.0.2.10:8443" {
		t.Errorf("got %q, want https://192.0.2.10:8443", got)
	}
}

func TestDefaultHubURL_PrefersTLSHostOverWildcardListenAddr(t *testing.T) {
	cfg := &config.HubConfig{ListenAddr: "0.0.0.0:8443", TLSHost: "hub.example.com"}
	got, err := defaultHubURL(cfg)
	if err != nil {
		t.Fatalf("defaultHubURL: %v", err)
	}
	if got != "https://hub.example.com:8443" {
		t.Errorf("got %q, want https://hub.example.com:8443", got)
	}
}

func testGenerateTokenConfig(dir string) *config.HubConfig {
	return &config.HubConfig{
		ListenAddr:  "127.0.0.1:8443",
		DataDir:     dir,
		DBPath:      filepath.Join(dir, "test.db"),
		TLSCertFile: filepath.Join(dir, "cert.pem"),
		TLSKeyFile:  filepath.Join(dir, "key.pem"),
	}
}

// seedRoute53Main opens cfg.DBPath's database (the same one runGenerateToken
// itself will open) and creates a route53_main DNS provider - runGenerateToken
// now validates dns_provider against the database, not cfg, so tests that
// need it to exist have to seed it there first.
func seedRoute53Main(t *testing.T, cfg *config.HubConfig) {
	t.Helper()
	st, err := hubstore.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store to seed dns provider: %v", err)
	}
	defer st.Close()
	if err := st.UpsertDNSProvider("route53_main", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("seed route53_main: %v", err)
	}
}

func TestRunGenerateToken_MissingRequiredArgsErrors(t *testing.T) {
	cfg := testGenerateTokenConfig(t.TempDir())
	if err := runGenerateToken(cfg, generateTokenArgs{}); err == nil {
		t.Fatal("expected an error for missing required args, got nil")
	}
}

func TestRunGenerateToken_UnknownDNSProviderErrors(t *testing.T) {
	cfg := testGenerateTokenConfig(t.TempDir())
	args := generateTokenArgs{
		SpokeID:     "radius-spoke",
		CertName:    "radius-cert",
		Domains:     "radius.example.com",
		DNSProvider: "does-not-exist",
		TTL:         time.Hour,
	}
	if err := runGenerateToken(cfg, args); err == nil {
		t.Fatal("expected an error for a dns_provider not defined in the hub config, got nil")
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// everything written to it - real output from the real function, not a
// mock of one, since runGenerateToken prints directly rather than
// returning what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return buf.String()
}

// TestRunGenerateToken_PrintedTokenIsGenuinelyRedeemable is the real
// end-to-end proof: capture what runGenerateToken actually prints, decode
// the token from it exactly as acme-spoke --load-token would, and confirm
// its secret is a real, redeemable row in the hub's real database - not
// just that the function returned without error.
func TestRunGenerateToken_PrintedTokenIsGenuinelyRedeemable(t *testing.T) {
	dir := t.TempDir()
	cfg := testGenerateTokenConfig(dir)
	seedRoute53Main(t, cfg)
	args := generateTokenArgs{
		SpokeID:     "radius-spoke",
		CertName:    "radius-cert",
		Domains:     "radius.example.com",
		DNSProvider: "route53_main",
		TTL:         time.Hour,
	}

	output := captureStdout(t, func() {
		if err := runGenerateToken(cfg, args); err != nil {
			t.Fatalf("runGenerateToken: %v", err)
		}
	})

	if _, err := os.Stat(cfg.TLSCertFile); err != nil {
		t.Fatalf("stat tls_cert_file after runGenerateToken (ensureTLS should have generated it): %v", err)
	}

	const marker = "--load-token "
	idx := strings.LastIndex(output, marker)
	if idx == -1 {
		t.Fatalf("printed output missing %q line:\n%s", marker, output)
	}
	tokenStr := strings.TrimSpace(output[idx+len(marker):])

	tok, err := enrolltoken.Decode(tokenStr)
	if err != nil {
		t.Fatalf("decode printed token: %v", err)
	}
	if tok.HubURL != "https://127.0.0.1:8443" {
		t.Errorf("got token hub_url %q, want https://127.0.0.1:8443 (defaulted from listen_addr)", tok.HubURL)
	}

	st, err := hubstore.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	spokeID, _, ok, err := st.LookupEnrollmentToken(tok.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("LookupEnrollmentToken: %v", err)
	}
	if !ok {
		t.Fatal("the printed token's secret is not a valid, redeemable enrollment token in the hub's database")
	}
	if spokeID != "radius-spoke" {
		t.Errorf("got spoke_id %q, want radius-spoke", spokeID)
	}
}
