package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/tmhal5l13/acme-agent/config"
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
