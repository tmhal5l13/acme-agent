package acmeclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/lego"

	"github.com/tmhal5l13/acme-agent/config"
)

func TestDirectoryURL_StagingAndProduction(t *testing.T) {
	got, err := DirectoryURL(config.ACMEConfig{Environment: "staging"})
	if err != nil {
		t.Fatalf("staging: unexpected error: %v", err)
	}
	if got != lego.LEDirectoryStaging {
		t.Errorf("staging: got %q, want %q", got, lego.LEDirectoryStaging)
	}

	got, err = DirectoryURL(config.ACMEConfig{Environment: "production"})
	if err != nil {
		t.Fatalf("production: unexpected error: %v", err)
	}
	if got != lego.LEDirectoryProduction {
		t.Errorf("production: got %q, want %q", got, lego.LEDirectoryProduction)
	}
}

// TestDirectoryURL_CustomOverridesEnvironment proves the actual point of
// this field: a private (or any non-Let's-Encrypt) CA's directory URL is
// used verbatim, not silently ignored in favor of Let's Encrypt's own URLs.
func TestDirectoryURL_CustomOverridesEnvironment(t *testing.T) {
	const custom = "https://private-ca.example.com/acme/directory"
	got, err := DirectoryURL(config.ACMEConfig{DirectoryURL: custom})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != custom {
		t.Errorf("got %q, want %q", got, custom)
	}
}

func TestDirectoryURL_UnknownEnvironmentErrors(t *testing.T) {
	if _, err := DirectoryURL(config.ACMEConfig{Environment: "not-a-real-environment"}); err == nil {
		t.Error("expected an error for an unknown environment, got nil")
	}
}

func TestHTTPClientFor_EmptyCACertFileReturnsNil(t *testing.T) {
	client, err := httpClientFor(config.ACMEConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client != nil {
		t.Error("got a non-nil client with no CACertFile set, want nil (lego's own default applies)")
	}
}

func TestHTTPClientFor_ValidCACertFileBuildsClient(t *testing.T) {
	certPath := writeTestCACert(t)

	client, err := httpClientFor(config.ACMEConfig{CACertFile: certPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("got a nil client with CACertFile set, want a real client trusting it")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("got Transport type %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Error("client's TLSClientConfig.RootCAs is nil - the custom CA was never actually wired in")
	}
}

func TestHTTPClientFor_MissingCACertFileErrors(t *testing.T) {
	if _, err := httpClientFor(config.ACMEConfig{CACertFile: "/nonexistent/path/ca.pem"}); err == nil {
		t.Error("expected an error for a nonexistent ca_cert_file, got nil")
	}
}

// writeTestCACert generates a real, syntactically valid self-signed
// certificate and writes it to a temp file, for tests that only need
// httpClientFor to successfully parse *a* certificate, not this specific
// one. Generated fresh rather than embedded as static PEM so there's no
// stale/expired test fixture to eventually rot.
func writeTestCACert(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write test CA cert: %v", err)
	}
	return path
}
