package selfsigned

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCert_GeneratesValidCertWithIPSAN(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := EnsureCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}

	cert := parseCert(t, certPath)
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("got IPAddresses %v, want [127.0.0.1]", cert.IPAddresses)
	}
	if len(cert.DNSNames) != 0 {
		t.Errorf("got DNSNames %v for an IP host, want none", cert.DNSNames)
	}
}

func TestEnsureCert_GeneratesValidCertWithDNSSAN(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := EnsureCert(certPath, keyPath, "hub.internal"); err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}

	cert := parseCert(t, certPath)
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "hub.internal" {
		t.Errorf("got DNSNames %v, want [hub.internal]", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 0 {
		t.Errorf("got IPAddresses %v for a DNS host, want none", cert.IPAddresses)
	}
}

func TestEnsureCert_KeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := EnsureCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("got key file mode %o, want 0600", perm)
	}
}

func TestEnsureCert_IdempotentAcrossExistingFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := EnsureCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("first EnsureCert: %v", err)
	}
	firstCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	if err := EnsureCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("second EnsureCert: %v", err)
	}
	secondCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	if string(firstCert) != string(secondCert) {
		t.Error("EnsureCert regenerated an already-existing certificate — this would invalidate every spoke's pinned copy on every hub restart")
	}
}

func parseCert(t *testing.T, certPath string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block found in generated cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
