package spokeagent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/hubclient"
	"github.com/tmhal5l13/acme-agent/internal/selfsigned"
	"github.com/tmhal5l13/acme-agent/internal/store"
)

// newTestHubClient builds a hubclient.Client for these tests. hubclient.New
// now requires a readable, parseable TLS cert file even though these tests
// talk to a plain-HTTP httptest.Server (the transport's TLSClientConfig
// simply goes unused for non-TLS requests) — a throwaway self-signed cert
// satisfies that without hardcoding a PEM fixture.
func newTestHubClient(t *testing.T, baseURL string) *hubclient.Client {
	t.Helper()
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	if err := selfsigned.EnsureCert(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("generate throwaway cert: %v", err)
	}
	hub, err := hubclient.New(baseURL, "test-token", certPath)
	if err != nil {
		t.Fatalf("hubclient.New: %v", err)
	}
	return hub
}

func TestBackoffFor(t *testing.T) {
	hour := time.Hour
	maxBackoff := 24 * time.Hour

	cases := []struct {
		failures int
		want     time.Duration
	}{
		{1, 1 * time.Hour},   // retryBackoff * 2^0
		{2, 2 * time.Hour},   // retryBackoff * 2^1
		{3, 4 * time.Hour},   // retryBackoff * 2^2
		{5, 16 * time.Hour},  // retryBackoff * 2^4
		{6, 24 * time.Hour},  // retryBackoff * 2^5 = 32h, capped at max
		{10, 24 * time.Hour}, // way past max, still capped
	}
	for _, c := range cases {
		got := backoffFor(c.failures, hour, maxBackoff)
		if got != c.want {
			t.Errorf("backoffFor(%d, %s, %s) = %s, want %s", c.failures, hour, maxBackoff, got, c.want)
		}
	}
}

func TestParseCertTimes(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	certPEM, wantSerial := generateTestCertPEM(t, notBefore, notAfter)

	gotNotBefore, gotNotAfter, gotSerial, err := parseCertTimes(certPEM)
	if err != nil {
		t.Fatalf("parseCertTimes: %v", err)
	}
	if !gotNotBefore.Equal(notBefore) {
		t.Errorf("got notBefore %s, want %s", gotNotBefore, notBefore)
	}
	if !gotNotAfter.Equal(notAfter) {
		t.Errorf("got notAfter %s, want %s", gotNotAfter, notAfter)
	}
	if gotSerial != wantSerial {
		t.Errorf("got serial %s, want %s", gotSerial, wantSerial)
	}
}

func TestParseCertTimes_InvalidPEM(t *testing.T) {
	if _, _, _, err := parseCertTimes([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for invalid PEM, got nil")
	}
}

// TestProcessIfDue_SkipsWhenBackingOff proves the local retry-backoff gate
// works without touching real ACME/DNS infrastructure: the fake hub always
// says "due", local state records a very recent failure, and the test
// fails immediately if the agent makes *any* hub call beyond the initial
// due-check (which would mean it proceeded into the real issuance pipeline
// instead of backing off).
func TestProcessIfDue_SkipsWhenBackingOff(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/certs/test-cert/due" {
			json.NewEncoder(w).Encode(map[string]bool{"due": true})
			return
		}
		t.Errorf("unexpected call to hub while backing off: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	// Seed local state: one recent failure, well within the 1h backoff
	// window.
	if _, err := st.GetOrCreateCertState("test-cert"); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	if _, err := st.MarkFailed("test-cert", errors.New("simulated failure")); err != nil {
		t.Fatalf("seed failure: %v", err)
	}

	cfg := &config.SpokeConfig{
		RequestTimeout:  config.Duration(5 * time.Second),
		RetryBackoff:    config.Duration(time.Hour),
		MaxRetryBackoff: config.Duration(24 * time.Hour),
	}
	hub := newTestHubClient(t, ts.URL)
	agent := New(cfg, st, hub)

	err = agent.processIfDue(context.Background(), config.SpokeLocalCertConfig{
		Name: "test-cert", Domains: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("processIfDue returned an error: %v", err)
	}
}

// TestFail_ReportsRealConsecutiveFailureCountToHub proves fail() sends the
// spoke's actual local failure-streak count (post-increment) to the hub,
// not just a fixed value or nothing at all — the hub has no other way to
// distinguish a certificate's first failed attempt from its fifth without
// this being reported accurately on every failed checkin.
func TestFail_ReportsRealConsecutiveFailureCountToHub(t *testing.T) {
	var capturedConsecutiveFailures = -1 // sentinel: checkin was never called
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/certs/test-cert/checkin" {
			var req hubclient.CheckinRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode checkin body: %v", err)
			}
			capturedConsecutiveFailures = req.ConsecutiveFailures
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	if _, err := st.GetOrCreateCertState("test-cert"); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	// Two prior failures already on record, so the next one (inside fail(),
	// below) must report 3 - proving the real, current count is used, not
	// a value that happens to be right only for a cert's very first failure.
	if _, err := st.MarkFailed("test-cert", errors.New("first")); err != nil {
		t.Fatalf("seed first failure: %v", err)
	}
	if _, err := st.MarkFailed("test-cert", errors.New("second")); err != nil {
		t.Fatalf("seed second failure: %v", err)
	}

	cfg := &config.SpokeConfig{RequestTimeout: config.Duration(5 * time.Second)}
	agent := New(cfg, st, newTestHubClient(t, ts.URL))

	returnedErr := agent.fail(context.Background(),
		config.SpokeLocalCertConfig{Name: "test-cert", Domains: []string{"example.com"}},
		errors.New("third"))
	if returnedErr == nil {
		t.Fatal("fail() returned nil, want the attempt error passed through")
	}

	if capturedConsecutiveFailures == -1 {
		t.Fatal("hub never received a checkin")
	}
	if capturedConsecutiveFailures != 3 {
		t.Errorf("got consecutive_failures %d reported to the hub, want 3", capturedConsecutiveFailures)
	}
}

// TestProcessIfDue_NotDueSkipsImmediately proves that when the hub says a
// cert isn't due, the agent doesn't even reach the local backoff check.
func TestProcessIfDue_NotDueSkipsImmediately(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/certs/test-cert/due" {
			json.NewEncoder(w).Encode(map[string]bool{"due": false})
			return
		}
		t.Errorf("unexpected call to hub for a not-due cert: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	cfg := &config.SpokeConfig{RequestTimeout: config.Duration(5 * time.Second)}
	hub := newTestHubClient(t, ts.URL)
	agent := New(cfg, st, hub)

	err = agent.processIfDue(context.Background(), config.SpokeLocalCertConfig{
		Name: "test-cert", Domains: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("processIfDue returned an error: %v", err)
	}
}

// generateTestCertPEM builds a minimal self-signed certificate valid over
// [notBefore, notAfter], returning its PEM encoding and decimal serial
// number string (matching x509.Certificate.SerialNumber.String(), the same
// format parseCertTimes returns).
func generateTestCertPEM(t *testing.T, notBefore, notAfter time.Time) (certPEM []byte, serial string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serialNumber := big.NewInt(123456789)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serialNumber.String()
}
