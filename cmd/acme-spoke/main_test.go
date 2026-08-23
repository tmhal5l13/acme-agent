package main

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/enrolltoken"
	"github.com/tmhal5l13/acme-agent/internal/hubapi"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
	"github.com/tmhal5l13/acme-agent/internal/selfsigned"
)

// startTLSServer mirrors internal/hubclient/client_test.go's helper of
// the same name - a real TLS listener presenting the given cert/key,
// serving handler.
func startTLSServer(t *testing.T, certPath, keyPath string, handler http.Handler) (addr string, shutdown func()) {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)

	return ln.Addr().String(), func() { srv.Close() }
}

func certFingerprintForTest(t *testing.T, certPath string) string {
	t.Helper()
	fp, err := selfsigned.Fingerprint(certPath)
	if err != nil {
		t.Fatalf("selfsigned.Fingerprint: %v", err)
	}
	return fp
}

// TestPinnedFingerprintClient_AcceptsMatchingCert mirrors
// internal/hubclient/client_test.go's TestClient_PinnedCertAccepted -
// same real-listener, no-mocks style, proving the fingerprint-pinning
// dial (this project's second independent implementation of certificate
// pinning, alongside hubclient.New's file-based one) actually works.
func TestPinnedFingerprintClient_AcceptsMatchingCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := selfsigned.EnsureCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	addr, shutdown := startTLSServer(t, certPath, keyPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer shutdown()

	var presentedDER []byte
	client := pinnedFingerprintClient(certFingerprintForTest(t, certPath), &presentedDER)

	resp, err := client.Get("https://" + addr)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want 200", resp.StatusCode)
	}
	if len(presentedDER) == 0 {
		t.Error("presentedDER was never set - VerifyPeerCertificate should have captured it on a successful handshake")
	}
}

// TestPinnedFingerprintClient_RejectsMismatchedCert is
// TestPinnedFingerprintClient_AcceptsMatchingCert's counterpart -
// mirrors TestClient_MismatchedCertRejected: a client pinned to a
// *different* certificate's fingerprint than the one the server actually
// presents must fail the handshake outright, proving this is genuine
// pinning and not "TLS is technically on."
func TestPinnedFingerprintClient_RejectsMismatchedCert(t *testing.T) {
	serverDir := t.TempDir()
	serverCertPath := filepath.Join(serverDir, "cert.pem")
	serverKeyPath := filepath.Join(serverDir, "key.pem")
	if err := selfsigned.EnsureCert(serverCertPath, serverKeyPath, "127.0.0.1"); err != nil {
		t.Fatalf("generate server cert: %v", err)
	}

	wrongDir := t.TempDir()
	wrongCertPath := filepath.Join(wrongDir, "cert.pem")
	wrongKeyPath := filepath.Join(wrongDir, "key.pem")
	if err := selfsigned.EnsureCert(wrongCertPath, wrongKeyPath, "127.0.0.1"); err != nil {
		t.Fatalf("generate wrong cert: %v", err)
	}

	addr, shutdown := startTLSServer(t, serverCertPath, serverKeyPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer shutdown()

	var presentedDER []byte
	client := pinnedFingerprintClient(certFingerprintForTest(t, wrongCertPath), &presentedDER)

	_, err := client.Get("https://" + addr)
	if err == nil {
		t.Fatal("expected an error dialing with a pinned fingerprint that doesn't match the server's certificate, got nil")
	}
	if len(presentedDER) != 0 {
		t.Error("presentedDER was set despite a fingerprint mismatch - VerifyPeerCertificate should have rejected before this could happen")
	}
}

// TestRunLoadToken_FullRoundTrip is the centerpiece test: a real
// hubapi.Server (with a real hubstore and a real inserted enrollment
// row) behind a real TLS listener, an enrollment token built exactly the
// way acme-hub --generate-token would, run through runLoadToken's real
// logic end to end, then the resulting config.yaml loaded through the
// real config.LoadSpokeConfig - proving the output is genuinely valid,
// working configuration, not just plausible-looking text (mirrors
// internal/onboard's own "round-trip through the real config loader"
// test discipline).
func TestRunLoadToken_FullRoundTrip(t *testing.T) {
	hubDir := t.TempDir()
	hubCertPath := filepath.Join(hubDir, "cert.pem")
	hubKeyPath := filepath.Join(hubDir, "key.pem")
	if err := selfsigned.EnsureCert(hubCertPath, hubKeyPath, "127.0.0.1"); err != nil {
		t.Fatalf("generate hub cert: %v", err)
	}

	const bearerToken = "the-real-bearer-token"
	const secret = "the-one-time-secret"

	hubCfg := &config.HubConfig{}

	st, err := hubstore.Open(filepath.Join(hubDir, "hub.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.UpsertDNSProvider("route53_main", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("UpsertDNSProvider: %v", err)
	}
	if err := st.CreateSpoke("radius-spoke", bearerToken); err != nil {
		t.Fatalf("CreateSpoke: %v", err)
	}
	if err := st.UpsertSpokeCert("radius-spoke", config.SpokeCertConfig{
		Name: "radius-cert", Domains: []string{"radius.example.com"}, DNSProvider: "route53_main",
	}); err != nil {
		t.Fatalf("UpsertSpokeCert: %v", err)
	}
	if err := st.InsertEnrollmentToken(secret, "radius-spoke", bearerToken, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	server, err := hubapi.NewServer(hubCfg, st)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	addr, shutdown := startTLSServer(t, hubCertPath, hubKeyPath, server.Handler())
	defer shutdown()

	tok := enrolltoken.Token{
		HubURL:      "https://" + addr,
		Fingerprint: certFingerprintForTest(t, hubCertPath),
		Secret:      secret,
	}
	encoded, err := tok.Encode()
	if err != nil {
		t.Fatalf("Token.Encode: %v", err)
	}

	spokeDir := t.TempDir()
	args := loadTokenArgs{
		Token:          encoded,
		ConfigOut:      filepath.Join(spokeDir, "config.yaml"),
		HubTLSCertFile: filepath.Join(spokeDir, "hub-cert.pem"),
		ACMEEmail:      "admin@example.com",
		ACMEEnv:        "staging",
	}
	if err := runLoadToken(args); err != nil {
		t.Fatalf("runLoadToken: %v", err)
	}

	// The pinned hub certificate must have been saved, and must be the
	// real hub certificate (not empty, not garbage).
	savedCertFingerprint := certFingerprintForTest(t, args.HubTLSCertFile)
	if savedCertFingerprint != tok.Fingerprint {
		t.Errorf("saved hub_tls_cert_file fingerprint %q, want %q", savedCertFingerprint, tok.Fingerprint)
	}

	// The generated config.yaml must actually load through the real
	// config loader, not just look plausible.
	t.Setenv("HUB_TOKEN", bearerToken)
	loaded, err := config.LoadSpokeConfig(args.ConfigOut)
	if err != nil {
		data, _ := os.ReadFile(args.ConfigOut)
		t.Fatalf("generated spoke config failed to load: %v\n--- generated YAML ---\n%s", err, data)
	}

	if loaded.HubURL != tok.HubURL {
		t.Errorf("got hub_url %q, want %q", loaded.HubURL, tok.HubURL)
	}
	if loaded.HubToken != bearerToken {
		t.Errorf("got hub_token %q, want the enrollment response's bearer token %q", loaded.HubToken, bearerToken)
	}
	if loaded.HubTLSCertFile != args.HubTLSCertFile {
		t.Errorf("got hub_tls_cert_file %q, want %q", loaded.HubTLSCertFile, args.HubTLSCertFile)
	}
	if len(loaded.Certs) != 1 || loaded.Certs[0].Name != "radius-cert" {
		t.Fatalf("got certs %+v, want one entry named radius-cert", loaded.Certs)
	}
	if len(loaded.Certs[0].Domains) != 1 || loaded.Certs[0].Domains[0] != "radius.example.com" {
		t.Errorf("got domains %v, want [radius.example.com]", loaded.Certs[0].Domains)
	}
}

// TestRunLoadToken_InvalidACMEEnvironmentErrors proves the CLI validates
// -acme-environment itself, before ever dialing the hub.
func TestRunLoadToken_InvalidACMEEnvironmentErrors(t *testing.T) {
	tok := enrolltoken.Token{HubURL: "https://127.0.0.1:1", Fingerprint: "abcd", Secret: "s"}
	encoded, err := tok.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	err = runLoadToken(loadTokenArgs{
		Token:     encoded,
		ConfigOut: filepath.Join(t.TempDir(), "config.yaml"),
		ACMEEnv:   "not-a-real-environment",
	})
	if err == nil {
		t.Fatal("expected an error for an invalid -acme-environment, got nil")
	}
}

func TestRunLoadToken_InvalidTokenErrors(t *testing.T) {
	err := runLoadToken(loadTokenArgs{
		Token:     "not a valid token",
		ConfigOut: filepath.Join(t.TempDir(), "config.yaml"),
		ACMEEnv:   "staging",
	})
	if err == nil {
		t.Fatal("expected an error decoding a garbage token, got nil")
	}
}
