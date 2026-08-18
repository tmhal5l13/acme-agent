package hubapi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

// pebbleE2EEnvVar mirrors internal/acmeclient's identically-named constant
// exactly - kept as a separate, duplicated definition rather than shared
// across packages, matching this codebase's existing convention of each
// package's tests being self-contained (see e.g. hubapi_test.go's own
// fakeDNSProvider vs. other packages' fakes).
const pebbleE2EEnvVar = "ACME_AGENT_E2E_TESTS"

func requirePebbleE2E(t *testing.T) {
	t.Helper()
	if _, ok := os.LookupEnv(pebbleE2EEnvVar); !ok {
		t.Skipf("skipping: e2e tests disabled (set %s=1 to enable)", pebbleE2EEnvVar)
	}
	if _, err := exec.LookPath("pebble"); err != nil {
		t.Skipf("skipping: pebble binary not found on $PATH (go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest)")
	}
	if _, err := exec.LookPath("pebble-challtestsrv"); err != nil {
		t.Skipf("skipping: pebble-challtestsrv binary not found on $PATH (go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest)")
	}
}

const (
	pebbleDirectoryURL    = "https://localhost:14000/dir"
	challSrvManagementURL = "http://localhost:8055"
	challSrvDNSAddr       = "localhost:8053"
)

// startPebble launches a real pebble subprocess and returns the CA
// certificate path a client must trust to dial it - fixtures shared with
// internal/acmeclient's identical helper (same underlying cert files,
// copied into this package's own testdata so each package's test file
// stays self-contained and independently runnable).
func startPebble(t *testing.T) (caCertFile string) {
	t.Helper()

	testdataDir, err := filepath.Abs(filepath.Join("testdata", "pebble"))
	if err != nil {
		t.Fatalf("resolve testdata path: %v", err)
	}
	caCertFile = filepath.Join(testdataDir, "pebble.minica.pem")

	configPath := filepath.Join(t.TempDir(), "pebble-config.json")
	configJSON := fmt.Sprintf(`{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": %q,
    "privateKey": %q,
    "httpPort": 5002,
    "tlsPort": 5001,
    "profiles": {
      "default": {"description": "default", "validityPeriod": 7776000}
    }
  }
}`, filepath.Join(testdataDir, "cert.pem"), filepath.Join(testdataDir, "key.pem"))
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatalf("write pebble config: %v", err)
	}

	cmd := exec.Command("pebble", "-config", configPath, "-dnsserver", challSrvDNSAddr)
	cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		t.Fatalf("start pebble: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		// cmd.Wait, not cmd.Process.Wait: the latter only reaps the OS
		// process and does not synchronize with Cmd's internal goroutine
		// copying stdout/stderr into output - reading output.String()
		// after only cmd.Process.Wait is a real data race (caught by
		// go test -race) against that still-running copy. An error here
		// is expected (the process was just killed) and not interesting.
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("pebble output:\n%s", output.String())
		}
	})

	waitForHTTPOK(t, pebbleDirectoryURL)
	return caCertFile
}

func startChallTestSrv(t *testing.T) {
	t.Helper()

	cmd := exec.Command("pebble-challtestsrv",
		"-http01", "", "-https01", "", "-tlsalpn01", "",
		"-dnsserver", ":8053",
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		t.Fatalf("start pebble-challtestsrv: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		// cmd.Wait, not cmd.Process.Wait: the latter only reaps the OS
		// process and does not synchronize with Cmd's internal goroutine
		// copying stdout/stderr into output - reading output.String()
		// after only cmd.Process.Wait is a real data race (caught by
		// go test -race) against that still-running copy. An error here
		// is expected (the process was just killed) and not interesting.
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("pebble-challtestsrv output:\n%s", output.String())
		}
	})

	waitForHTTPOK(t, challSrvManagementURL+"/set-default-ipv4")
}

func waitForHTTPOK(t *testing.T, url string) {
	t.Helper()

	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // test-only health check, not a security-relevant connection
	}

	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to respond: %v", url, lastErr)
}

// challTestSrvProvider is the hub's registered challenge.Provider for the
// "pebble" dns_provider entry in this test - identical in spirit to
// internal/acmeclient's own copy (see that package's pebble_helpers_test.go
// for why it's duplicated rather than shared), except here it stands in
// for a real DNS provider on the *hub* side, relayed to over HTTP by
// hubclient.DNS01Provider exactly like a real one would be.
type challTestSrvProvider struct{}

func (challTestSrvProvider) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	return challTestSrvPost("/set-txt", map[string]string{"host": fqdn, "value": value})
}

func (challTestSrvProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	return challTestSrvPost("/clear-txt", map[string]string{"host": fqdn})
}

func challTestSrvPost(path string, body map[string]string) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode challtestsrv request: %w", err)
	}
	resp, err := http.Post(challSrvManagementURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("challtestsrv %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challtestsrv %s: status %s", path, resp.Status)
	}
	return nil
}

// startHubTLSServer runs s.Handler() behind a real TLS listener using a
// real internal/selfsigned certificate - mirroring cmd/acme-hub's own
// ListenAndServeTLS exactly, and internal/hubclient/client_test.go's
// startTLSServer helper, so this test exercises the real hub binary's
// serving shape rather than httptest's in-memory transport.
func startHubTLSServer(t *testing.T, s *Server, certPath, keyPath string) (addr string, shutdown func()) {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load hub key pair: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{Handler: s.Handler()}
	go srv.Serve(ln)

	return ln.Addr().String(), func() { srv.Close() }
}
