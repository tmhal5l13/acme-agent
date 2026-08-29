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
// works without touching real ACME/DNS infrastructure or the hub at all -
// local state records a very recent failure, and the test fails if the
// agent makes *any* hub call whatsoever. Backoff is deliberately checked
// before ever calling the hub's /due (which, since it also atomically
// claims a renewal lease when it answers "due" - see internal/hubapi's
// handleDue - would otherwise claim a lease for an attempt that's about
// to be skipped anyway, left dangling until it self-expired). The fake
// hub server below has no handler at all for /due, on purpose: if
// anything reaches it, that alone is the bug this test exists to catch.
func TestProcessIfDue_SkipsWhenBackingOff(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestHookTimeoutFor_PerCertOverrideWinsOverGlobal(t *testing.T) {
	cfg := &config.SpokeConfig{HookTimeout: config.Duration(30 * time.Second)}
	agent := New(cfg, nil, nil)

	withOverride := config.SpokeLocalCertConfig{Name: "test-cert", HookTimeout: config.Duration(5 * time.Second)}
	if got := agent.hookTimeoutFor(withOverride); got != 5*time.Second {
		t.Errorf("got %s with a per-cert override set, want the override (5s), not the global default", got)
	}

	withoutOverride := config.SpokeLocalCertConfig{Name: "test-cert"}
	if got := agent.hookTimeoutFor(withoutOverride); got != 30*time.Second {
		t.Errorf("got %s with no per-cert override, want the spoke-wide default (30s)", got)
	}
}

// TestReportHookResult_SendsHookStatusToHub proves a hook result actually
// reaches the hub as a checkin carrying the new hook_status/hook_error/hook_at
// fields, using the certificate's given validity window and serial rather
// than describing a new certificate.
func TestReportHookResult_SendsHookStatusToHub(t *testing.T) {
	var captured hubclient.CheckinRequest
	var checkinCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/certs/test-cert/checkin" {
			checkinCount++
			if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
				t.Errorf("decode checkin body: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	cfg := &config.SpokeConfig{RequestTimeout: config.Duration(5 * time.Second)}
	agent := New(cfg, nil, newTestHubClient(t, ts.URL))

	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	cert := config.SpokeLocalCertConfig{Name: "test-cert", Domains: []string{"example.com"}, ReloadHook: "exit 1"}

	agent.reportHookResult(context.Background(), cert, notBefore, notAfter, "serial-1", errors.New("fmsadmin certificate import failed"))

	if checkinCount != 1 {
		t.Fatalf("got %d checkins, want exactly 1", checkinCount)
	}
	if captured.Status != "active" {
		t.Errorf("got status %q, want %q (a hook failure must not report the certificate itself as failed)", captured.Status, "active")
	}
	if captured.HookStatus != "failed" {
		t.Errorf("got hook_status %q, want %q", captured.HookStatus, "failed")
	}
	if captured.HookError != "fmsadmin certificate import failed" {
		t.Errorf("got hook_error %q, want the reported error", captured.HookError)
	}
	if captured.HookAt.IsZero() {
		t.Error("got zero hook_at, want it set")
	}
	if !captured.NotBefore.Equal(notBefore) || !captured.NotAfter.Equal(notAfter) || captured.Serial != "serial-1" {
		t.Errorf("got cert fields (%v, %v, %q), want the given (%v, %v, %q) unchanged",
			captured.NotBefore, captured.NotAfter, captured.Serial, notBefore, notAfter, "serial-1")
	}
}

func TestReportHookResult_SuccessReportsHookStatusOK(t *testing.T) {
	var captured hubclient.CheckinRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&captured)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	cfg := &config.SpokeConfig{RequestTimeout: config.Duration(5 * time.Second)}
	agent := New(cfg, nil, newTestHubClient(t, ts.URL))
	cert := config.SpokeLocalCertConfig{Name: "test-cert", Domains: []string{"example.com"}, ReloadHook: "exit 0"}

	agent.reportHookResult(context.Background(), cert, time.Now(), time.Now().Add(time.Hour), "serial-1", nil)

	if captured.HookStatus != "ok" {
		t.Errorf("got hook_status %q for a successful hook, want %q", captured.HookStatus, "ok")
	}
	if captured.HookError != "" {
		t.Errorf("got hook_error %q for a successful hook, want empty", captured.HookError)
	}
}

// TestReportHookResult_NoOpWhenNoReloadHookConfigured proves a cert with
// no reload_hook never calls the hub at all - nothing to report. The fake
// hub errors on any request, exactly like TestProcessIfDue_SkipsWhenBackingOff's.
func TestReportHookResult_NoOpWhenNoReloadHookConfigured(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected call to hub for a cert with no reload_hook: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	cfg := &config.SpokeConfig{RequestTimeout: config.Duration(5 * time.Second)}
	agent := New(cfg, nil, newTestHubClient(t, ts.URL))
	cert := config.SpokeLocalCertConfig{Name: "test-cert", Domains: []string{"example.com"}} // no ReloadHook

	agent.reportHookResult(context.Background(), cert, time.Now(), time.Now().Add(time.Hour), "serial-1", nil)
}

// TestRetryHookIfFailed_RetriesAndReportsWhenLastHookFailed is the actual
// point of this mechanism: a reload_hook that failed on the last real
// issuance gets retried on a later poll cycle, without waiting for the
// certificate's own next renewal (weeks to months away) - and the hub
// finds out either way, not just on success.
func TestRetryHookIfFailed_RetriesAndReportsWhenLastHookFailed(t *testing.T) {
	var captured hubclient.CheckinRequest
	var checkinCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkinCount++
		json.NewDecoder(r.Body).Decode(&captured)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	if _, err := st.GetOrCreateCertState("test-cert"); err != nil {
		t.Fatalf("seed state row: %v", err)
	}
	notBefore, notAfter := time.Now(), time.Now().Add(60*24*time.Hour)
	if err := st.MarkIssued("test-cert", notBefore, notAfter, "serial-1"); err != nil {
		t.Fatalf("seed issued state: %v", err)
	}
	// The previous hook run failed - this is what retryHookIfFailed looks
	// for to decide there's anything to retry at all.
	if err := st.MarkHookResult("test-cert", errors.New("previous failure")); err != nil {
		t.Fatalf("seed prior hook failure: %v", err)
	}

	cfg := &config.SpokeConfig{RequestTimeout: config.Duration(5 * time.Second), HookTimeout: config.Duration(5 * time.Second)}
	agent := New(cfg, st, newTestHubClient(t, ts.URL))
	// A command that succeeds this time - retrying is supposed to have
	// fixed it (e.g. the operator corrected the reload_hook command).
	cert := config.SpokeLocalCertConfig{Name: "test-cert", Domains: []string{"example.com"}, ReloadHook: "exit 0"}

	cs, err := st.GetOrCreateCertState("test-cert")
	if err != nil {
		t.Fatalf("load local state: %v", err)
	}
	agent.retryHookIfFailed(context.Background(), cert, cs)

	if checkinCount != 1 {
		t.Fatalf("got %d checkins, want exactly 1 (the retry's own report)", checkinCount)
	}
	if captured.HookStatus != "ok" {
		t.Errorf("got hook_status %q after a successful retry, want %q", captured.HookStatus, "ok")
	}

	updated, err := st.GetOrCreateCertState("test-cert")
	if err != nil {
		t.Fatalf("reload local state: %v", err)
	}
	if updated.LastHookError.Valid {
		t.Errorf("got last_hook_error %v locally after a successful retry, want cleared", updated.LastHookError)
	}
}

// TestRetryHookIfFailed_NoOpWhenLastHookSucceeded proves a cert whose last
// hook run already succeeded is left alone on later poll cycles - nothing
// to retry, so neither the hook itself nor the hub should be touched. The
// configured reload_hook would fail loudly if it were actually run
// (referencing a binary that doesn't exist), so a checkin ever arriving
// would mean it ran when it shouldn't have.
func TestRetryHookIfFailed_NoOpWhenLastHookSucceeded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected call to hub when the last hook run already succeeded: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	if _, err := st.GetOrCreateCertState("test-cert"); err != nil {
		t.Fatalf("seed state row: %v", err)
	}
	if err := st.MarkIssued("test-cert", time.Now(), time.Now().Add(60*24*time.Hour), "serial-1"); err != nil {
		t.Fatalf("seed issued state: %v", err)
	}
	// No MarkHookResult failure seeded - last_hook_error stays NULL,
	// matching "never run" and "last run succeeded" alike.

	cfg := &config.SpokeConfig{RequestTimeout: config.Duration(5 * time.Second), HookTimeout: config.Duration(5 * time.Second)}
	agent := New(cfg, st, newTestHubClient(t, ts.URL))
	cert := config.SpokeLocalCertConfig{Name: "test-cert", Domains: []string{"example.com"}, ReloadHook: "this-binary-does-not-exist-anywhere"}

	cs, err := st.GetOrCreateCertState("test-cert")
	if err != nil {
		t.Fatalf("load local state: %v", err)
	}
	agent.retryHookIfFailed(context.Background(), cert, cs)
}

// TestProcessIfDue_RetriesFailedHookWhenNotDue is the integration version
// of the two RetryHookIfFailed unit tests above, proving processIfDue
// itself actually wires this in on the "not due" path.
func TestProcessIfDue_RetriesFailedHookWhenNotDue(t *testing.T) {
	var sawHookCheckin bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/certs/test-cert/due" {
			json.NewEncoder(w).Encode(map[string]bool{"due": false})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/v1/certs/test-cert/checkin" {
			var req hubclient.CheckinRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.HookStatus == "ok" {
				sawHookCheckin = true
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Errorf("unexpected call to hub: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	if _, err := st.GetOrCreateCertState("test-cert"); err != nil {
		t.Fatalf("seed state row: %v", err)
	}
	if err := st.MarkIssued("test-cert", time.Now(), time.Now().Add(60*24*time.Hour), "serial-1"); err != nil {
		t.Fatalf("seed issued state: %v", err)
	}
	if err := st.MarkHookResult("test-cert", errors.New("previous failure")); err != nil {
		t.Fatalf("seed prior hook failure: %v", err)
	}

	cfg := &config.SpokeConfig{RequestTimeout: config.Duration(5 * time.Second), HookTimeout: config.Duration(5 * time.Second)}
	agent := New(cfg, st, newTestHubClient(t, ts.URL))
	cert := config.SpokeLocalCertConfig{Name: "test-cert", Domains: []string{"example.com"}, ReloadHook: "exit 0"}

	if err := agent.processIfDue(context.Background(), cert); err != nil {
		t.Fatalf("processIfDue: %v", err)
	}
	if !sawHookCheckin {
		t.Error("processIfDue did not retry the failed hook (or didn't report it) when the cert wasn't due for renewal")
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
