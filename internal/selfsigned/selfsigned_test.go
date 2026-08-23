package selfsigned

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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

func TestGenerateCert_ProducesValidCertWithIPSAN(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := GenerateCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("GenerateCert: %v", err)
	}

	cert := parseCert(t, certPath)
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("got IPAddresses %v, want [127.0.0.1]", cert.IPAddresses)
	}
}

func TestGenerateCert_KeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := GenerateCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("GenerateCert: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("got key file mode %o, want 0600", perm)
	}
}

// TestGenerateCert_OverwritesExistingFilesUnconditionally is the
// property that distinguishes GenerateCert from EnsureCert (see
// TestEnsureCert_IdempotentAcrossExistingFiles for the opposite
// guarantee): calling it again against an already-populated path must
// produce a genuinely new certificate, not silently reuse the old one —
// this is what makes it usable to generate a "next" candidate cert for
// hub TLS rotation.
func TestGenerateCert_OverwritesExistingFilesUnconditionally(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := GenerateCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("first GenerateCert: %v", err)
	}
	firstCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	firstKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	if err := GenerateCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("second GenerateCert: %v", err)
	}
	secondCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	secondKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	if string(firstCert) == string(secondCert) {
		t.Error("GenerateCert produced an identical certificate on a second call, want a genuinely new one each time")
	}
	if string(firstKey) == string(secondKey) {
		t.Error("GenerateCert produced an identical key on a second call, want a genuinely new one each time")
	}
}

// TestFingerprint_MatchesDirectComputation proves Fingerprint's value is
// exactly sha256(parsed certificate's DER bytes) - the same computation
// its callers (cmd/acme-hub's startup log line, internal/enrolltoken)
// need to match independently elsewhere, not some other encoding that
// happens to look plausible.
func TestFingerprint_MatchesDirectComputation(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := GenerateCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("GenerateCert: %v", err)
	}

	got, err := Fingerprint(certPath)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}

	cert := parseCert(t, certPath)
	sum := sha256.Sum256(cert.Raw)
	want := hex.EncodeToString(sum[:])

	if got != want {
		t.Errorf("Fingerprint returned %q, want %q (sha256 of the parsed certificate's DER bytes)", got, want)
	}
}

func TestFingerprint_DifferentCertsHaveDifferentFingerprints(t *testing.T) {
	dir := t.TempDir()
	certA := filepath.Join(dir, "a.pem")
	keyA := filepath.Join(dir, "a-key.pem")
	certB := filepath.Join(dir, "b.pem")
	keyB := filepath.Join(dir, "b-key.pem")
	if err := GenerateCert(certA, keyA, "127.0.0.1"); err != nil {
		t.Fatalf("GenerateCert a: %v", err)
	}
	if err := GenerateCert(certB, keyB, "127.0.0.1"); err != nil {
		t.Fatalf("GenerateCert b: %v", err)
	}

	fpA, err := Fingerprint(certA)
	if err != nil {
		t.Fatalf("Fingerprint a: %v", err)
	}
	fpB, err := Fingerprint(certB)
	if err != nil {
		t.Fatalf("Fingerprint b: %v", err)
	}
	if fpA == fpB {
		t.Error("got identical fingerprints for two independently generated certificates, want different")
	}
}

func TestFingerprint_MissingFileErrors(t *testing.T) {
	if _, err := Fingerprint("/does/not/exist.pem"); err == nil {
		t.Fatal("expected an error for a nonexistent cert file, got nil")
	}
}

func TestFingerprint_InvalidFileErrors(t *testing.T) {
	dir := t.TempDir()
	badCert := filepath.Join(dir, "not-a-cert.pem")
	if err := os.WriteFile(badCert, []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if _, err := Fingerprint(badCert); err == nil {
		t.Fatal("expected an error for a file with no valid PEM certificate, got nil")
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
