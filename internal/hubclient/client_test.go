package hubclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tmhal5l13/acme-agent/internal/selfsigned"
)

// startTLSServer runs a real TLS server (mirroring exactly how cmd/acme-hub
// serves — a cert/key pair from internal/selfsigned) that answers /due, and
// returns its address and a shutdown func.
func startTLSServer(t *testing.T, certPath, keyPath string) (addr string, shutdown func()) {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]bool{"due": true})
		}),
	}
	go srv.Serve(ln)

	return ln.Addr().String(), func() { srv.Close() }
}

func TestClient_PinnedCertAccepted(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := selfsigned.EnsureCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	addr, shutdown := startTLSServer(t, certPath, keyPath)
	defer shutdown()

	client, err := New("https://"+addr, "test-token", certPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	due, err := client.Due(ctx, "some-cert")
	if err != nil {
		t.Fatalf("Due: %v", err)
	}
	if !due {
		t.Error("got due=false, want true")
	}
}

// TestClient_MismatchedCertRejected is the test that actually proves this
// is certificate pinning and not just "TLS is technically on": a client
// pinned to a *different* self-signed certificate than the one the server
// presents must fail the handshake, not silently succeed.
func TestClient_MismatchedCertRejected(t *testing.T) {
	serverDir := t.TempDir()
	serverCertPath := filepath.Join(serverDir, "cert.pem")
	serverKeyPath := filepath.Join(serverDir, "key.pem")
	if err := selfsigned.EnsureCert(serverCertPath, serverKeyPath, "127.0.0.1"); err != nil {
		t.Fatalf("generate server cert: %v", err)
	}

	// A completely different certificate — what the client will pin instead
	// of the server's real one.
	wrongDir := t.TempDir()
	wrongCertPath := filepath.Join(wrongDir, "cert.pem")
	wrongKeyPath := filepath.Join(wrongDir, "key.pem")
	if err := selfsigned.EnsureCert(wrongCertPath, wrongKeyPath, "127.0.0.1"); err != nil {
		t.Fatalf("generate wrong cert: %v", err)
	}

	addr, shutdown := startTLSServer(t, serverCertPath, serverKeyPath)
	defer shutdown()

	client, err := New("https://"+addr, "test-token", wrongCertPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.Due(ctx, "some-cert")
	if err == nil {
		t.Fatal("expected an error connecting with a pinned certificate that doesn't match the server's, got nil")
	}
}

// startTLSServerCappedAtTLS12 is startTLSServer with the server's own
// MaxVersion capped at TLS 1.2, for proving New's MinVersion pin actually
// rejects a peer that can't speak TLS 1.3 rather than just being set and
// never enforced.
func startTLSServerCappedAtTLS12(t *testing.T, certPath, keyPath string) (addr string, shutdown func()) {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MaxVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]bool{"due": true})
		}),
	}
	go srv.Serve(ln)

	return ln.Addr().String(), func() { srv.Close() }
}

// TestNew_RejectsServerBelowTLS13 proves the MinVersion pin in New's
// tls.Config is actually enforced, not just set - a server that can't
// negotiate above TLS 1.2 must fail the handshake outright.
func TestNew_RejectsServerBelowTLS13(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := selfsigned.EnsureCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	addr, shutdown := startTLSServerCappedAtTLS12(t, certPath, keyPath)
	defer shutdown()

	client, err := New("https://"+addr, "test-token", certPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Due(ctx, "some-cert"); err == nil {
		t.Fatal("expected a handshake error against a server capped at TLS 1.2, got nil")
	}
}

func TestNew_UnreadableCertFileErrors(t *testing.T) {
	_, err := New("https://127.0.0.1:1", "test-token", "/does/not/exist.pem")
	if err == nil {
		t.Fatal("expected an error for a nonexistent cert file, got nil")
	}
}

func TestNew_InvalidCertFileErrors(t *testing.T) {
	dir := t.TempDir()
	badCert := filepath.Join(dir, "not-a-cert.pem")
	if err := os.WriteFile(badCert, []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := New("https://127.0.0.1:1", "test-token", badCert)
	if err == nil {
		t.Fatal("expected an error for a cert file with no valid PEM certificate, got nil")
	}
}
