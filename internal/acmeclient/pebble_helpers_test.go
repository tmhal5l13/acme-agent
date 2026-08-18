package acmeclient

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

// pebbleE2EEnvVar gates every test in this file: unset means skip with a
// clear message, not fail, so `go test ./...` stays green on a machine
// without pebble/pebble-challtestsrv installed. Mirrors the exact pattern
// lego's own e2e test suite uses for its LEGO_E2E_TESTS env var.
const pebbleE2EEnvVar = "ACME_AGENT_E2E_TESTS"

// requirePebbleE2E skips the calling test unless e2e testing is explicitly
// enabled and both required binaries are actually on $PATH. Called first
// thing by every test in this file, not just once via TestMain, so `go test
// -run` against a single test still gets a clear skip reason rather than a
// confusing failure.
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

// startPebble launches a real pebble subprocess configured to validate
// DNS-01 challenges against pebble-challtestsrv's mock DNS server, waits
// for its ACME directory to answer, and registers a cleanup to kill it.
// Returns the path to the CA certificate a client must trust to dial
// pebble's TLS listener (see internal/acmeclient/testdata/pebble).
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

	// PEBBLE_VA_NOSLEEP=1 removes pebble's deliberate 0-15s random sleep
	// between challenge validation attempts, so this test runs at full
	// speed instead of exercising lego's own polling/retry loop.
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

// startChallTestSrv launches pebble-challtestsrv with only its DNS-01
// responder enabled (HTTP-01/TLS-ALPN-01/A/AAAA all disabled - this suite
// only exercises DNS-01, matching how internal/hubclient.DNS01Provider
// relays challenges in production) and registers a cleanup to kill it.
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

// waitForHTTPOK polls url (accepting any TLS certificate, since this is
// only ever used to detect "is the process accepting connections yet",
// not to validate its identity) until it responds or the deadline passes.
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

// challTestSrvProvider is a lego challenge.Provider backed directly by
// pebble-challtestsrv's DNS-01 management API (POST /set-txt, /clear-txt -
// see cmd/pebble-challtestsrv/README.md in the pebble repo). This is
// deliberately not internal/dnsprovider or lego's own httpreq provider -
// it exists only to drive this test's DNS-01 challenges against
// pebble-challtestsrv's mock DNS server, the same role
// internal/hubclient.DNS01Provider plays against a real DNS provider in
// production, kept intentionally separate from product code.
type challTestSrvProvider struct{}

func (challTestSrvProvider) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	return challTestSrvSetTXT(fqdn, value)
}

func (challTestSrvProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	return challTestSrvClearTXT(fqdn)
}

func challTestSrvSetTXT(fqdn, value string) error {
	return challTestSrvPost("/set-txt", map[string]string{"host": fqdn, "value": value})
}

func challTestSrvClearTXT(fqdn string) error {
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
