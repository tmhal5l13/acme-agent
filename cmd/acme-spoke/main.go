// Command acme-spoke is the spoke agent: it generates its own key, drives
// its own ACME order, installs the resulting certificate locally, and runs
// its own local reload hook. It polls the hub for renewal instructions and
// relays DNS-01 challenges through it, but never sends the hub a private
// key or DNS provider credential — those never leave this host (or, for
// DNS credentials, never arrive on it at all).
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/enrolltoken"
	"github.com/tmhal5l13/acme-agent/internal/hubclient"
	"github.com/tmhal5l13/acme-agent/internal/onboard"
	"github.com/tmhal5l13/acme-agent/internal/secureperm"
	"github.com/tmhal5l13/acme-agent/internal/spokeagent"
	"github.com/tmhal5l13/acme-agent/internal/store"
	"github.com/tmhal5l13/acme-agent/internal/umask"
)

func main() {
	if err := run(); err != nil {
		slog.Error("acme-spoke exiting", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "./config.yaml", "path to this spoke's config.yaml")
	once := flag.Bool("once", false, "run a single pass over all certificates, then exit (default: run as a daemon)")

	loadToken := flag.String("load-token", "", "one-time enrollment token from acme-hub --generate-token; if set, writes config.yaml and exits instead of running as a daemon")
	ltConfigOut := flag.String("config-out", "./config.yaml", "(-load-token) where to write the generated config.yaml")
	ltHubTLSCertFile := flag.String("hub-tls-cert-file", "/etc/acme-spoke/hub-cert.pem", "(-load-token) where to save the hub's TLS certificate, pinned during enrollment")
	ltACMEEmail := flag.String("acme-email", "", "(-load-token) ACME account email for this spoke")
	ltACMEEnv := flag.String("acme-environment", "staging", "(-load-token) staging or production")

	flag.Parse()

	umask.Restrict()

	if *loadToken != "" {
		return runLoadToken(loadTokenArgs{
			Token:          *loadToken,
			ConfigOut:      *ltConfigOut,
			HubTLSCertFile: *ltHubTLSCertFile,
			ACMEEmail:      *ltACMEEmail,
			ACMEEnv:        *ltACMEEnv,
		})
	}

	cfg, err := config.LoadSpokeConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data_dir: %w", err)
	}
	if err := os.Chmod(cfg.DataDir, 0o750); err != nil { // MkdirAll's mode is subject to umask; chmod explicitly
		return fmt.Errorf("chmod data_dir: %w", err)
	}
	if err := secureperm.Protect(cfg.DataDir); err != nil {
		return fmt.Errorf("protect data_dir: %w", err)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	hub, err := hubclient.New(cfg.HubURL, cfg.HubToken, cfg.HubTLSCertFile)
	if err != nil {
		return fmt.Errorf("build hub client: %w", err)
	}
	agent := spokeagent.New(cfg, st, hub)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		agent.RunOnce(ctx)
		return nil
	}

	agent.Run(ctx)
	return nil
}

// loadTokenArgs is the -load-token flag group, gathered into one struct
// so runLoadToken doesn't take five separate parameters.
type loadTokenArgs struct {
	Token          string
	ConfigOut      string
	HubTLSCertFile string
	ACMEEmail      string
	ACMEEnv        string
}

const (
	// enrollRetryInterval/enrollRetryTimeout bound how long -load-token
	// keeps retrying a 503 ("spoke not yet configured on the hub" - see
	// internal/hubapi's handleEnroll) before giving up. The operator is
	// expected to be actively pasting the printed snippet and reloading
	// the hub around the same time they run this command, so a real wait
	// (not an immediate failure) is the point - but it can't be
	// unbounded, since a mistyped spoke id or a forgotten reload would
	// otherwise hang forever with no clear signal why.
	enrollRetryInterval = 5 * time.Second
	enrollRetryTimeout  = 5 * time.Minute
)

// enrollResponse mirrors internal/hubapi's enrollResponse JSON shape.
// Deliberately a separate local type, not a shared import - the same
// pattern internal/hubclient/provider.go already uses for dns01Request,
// matching the hub's wire format by field/tag rather than importing an
// internal hubapi type cross-binary.
type enrollResponse struct {
	SpokeID     string `json:"spoke_id"`
	BearerToken string `json:"bearer_token"`
	Certs       []struct {
		Name    string   `json:"name"`
		Domains []string `json:"domains"`
	} `json:"certs"`
}

// runLoadToken is -load-token's entire job: decode the token from
// acme-hub --generate-token, dial the hub while verifying its identity
// cryptographically (see pinnedFingerprintClient), redeem the enrollment
// secret, and write a complete, working config.yaml with the hub's
// certificate already pinned - no manual file copying anywhere in this
// path. See ARCHITECTURE.md "Spoke enrollment" for the full workflow.
func runLoadToken(args loadTokenArgs) error {
	tok, err := enrolltoken.Decode(args.Token)
	if err != nil {
		return fmt.Errorf("decode token: %w", err)
	}
	if args.ACMEEnv != "staging" && args.ACMEEnv != "production" {
		return fmt.Errorf("acme environment must be %q or %q, got %q", "staging", "production", args.ACMEEnv)
	}

	var hubCertDER []byte
	client := pinnedFingerprintClient(tok.Fingerprint, &hubCertDER)

	resp, err := enrollWithRetry(client, tok.HubURL, tok.Secret)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(args.HubTLSCertFile), 0o755); err != nil {
		return fmt.Errorf("create hub_tls_cert_file directory: %w", err)
	}
	hubCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hubCertDER})
	if err := os.WriteFile(args.HubTLSCertFile, hubCertPEM, 0o644); err != nil {
		return fmt.Errorf("write hub tls cert file: %w", err)
	}

	certs := make([]onboard.SpokeCert, 0, len(resp.Certs))
	for _, c := range resp.Certs {
		certs = append(certs, onboard.SpokeCert{Name: c.Name, Domains: c.Domains})
	}
	spokeConfigYAML := onboard.BuildSpokeConfigYAML(onboard.SpokeConfigParams{
		HubURL:         tok.HubURL,
		HubTLSCertFile: args.HubTLSCertFile,
		ACMEEnv:        args.ACMEEnv,
		ACMEEmail:      args.ACMEEmail,
	}, certs)
	if err := os.WriteFile(args.ConfigOut, []byte(spokeConfigYAML), 0o644); err != nil {
		return fmt.Errorf("write config.yaml: %w", err)
	}

	fmt.Printf("Enrolled as spoke %q. Wrote %s and %s.\n\n", resp.SpokeID, args.ConfigOut, args.HubTLSCertFile)
	fmt.Println("=== Add to this spoke's acme-spoke.env ===")
	fmt.Printf("HUB_TOKEN=%s\n\n", resp.BearerToken)
	fmt.Printf("Review the commented-out reload_hook placeholders in %s, then:\n", args.ConfigOut)
	fmt.Println("  sudo ./deploy/install-spoke.sh   # if not already installed")
	fmt.Println("  systemctl enable --now acme-spoke")

	return nil
}

// pinnedFingerprintClient builds an http.Client that trusts exactly one
// certificate - identified by its SHA-256 fingerprint, not a file already
// on disk - during the TLS handshake itself. *presentedDER is set to the
// verified leaf certificate's raw DER bytes on a successful connection,
// so the caller can save the exact certificate that was actually pinned.
//
// InsecureSkipVerify is safe here only because VerifyPeerCertificate
// below independently re-verifies before any application data is sent:
// InsecureSkipVerify disables Go's *default* chain-of-trust check
// (hostname match, expiry, a trusted CA chain) - none of which apply yet,
// since this spoke has no pinned file to check against until this exact
// call succeeds. VerifyPeerCertificate runs after the handshake's
// certificate exchange but before the connection is handed back as
// usable; returning a non-nil error aborts the handshake outright, so an
// unrecognized certificate never gets the chance to receive the
// enrollment secret. This is the same pinning trust model
// internal/hubclient.New already uses (a RootCAs pool built from a
// pre-copied file) - the only difference is the trusted value comes from
// the enrollment token's embedded fingerprint instead of a file, with the
// same real out-of-band provenance (the operator who ran
// acme-hub --generate-token) that today's manual fingerprint-eyeballing
// step already relies on. It is not trust-on-first-use.
func pinnedFingerprintClient(wantFingerprint string, presentedDER *[]byte) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // see doc comment above
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return fmt.Errorf("hub presented no certificate")
					}
					sum := sha256.Sum256(rawCerts[0])
					got := hex.EncodeToString(sum[:])
					if got != wantFingerprint {
						return fmt.Errorf("hub certificate fingerprint mismatch: got %s, want %s", got, wantFingerprint)
					}
					// rawCerts[0] is already the DER-encoded leaf
					// certificate - the same bytes selfsigned.Fingerprint
					// hashes, so this comparison needs no extra parsing.
					*presentedDER = rawCerts[0]
					return nil
				},
			},
		},
	}
}

// enrollWithRetry POSTs secret to hubURL+"/v1/enroll", retrying on 503
// ("spoke not yet configured on the hub" - see internal/hubapi's
// handleEnroll) for up to enrollRetryTimeout. Any other non-200 response
// (invalid/expired/already-redeemed secret, or a real error) fails
// immediately - only "not configured yet" is worth waiting out.
func enrollWithRetry(client *http.Client, hubURL, secret string) (*enrollResponse, error) {
	deadline := time.Now().Add(enrollRetryTimeout)
	for {
		resp, status, err := postEnroll(client, hubURL, secret)
		if status == http.StatusServiceUnavailable {
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("hub still reports this spoke isn't configured after %s - add the printed hub-config snippet under spokes: and reload the hub, then try again: %w", enrollRetryTimeout, err)
			}
			slog.Info("hub reports spoke not yet configured, retrying", "retry_in", enrollRetryInterval)
			time.Sleep(enrollRetryInterval)
			continue
		}
		return resp, err
	}
}

func postEnroll(client *http.Client, hubURL, secret string) (*enrollResponse, int, error) {
	body, err := json.Marshal(map[string]string{"secret": secret})
	if err != nil {
		return nil, 0, fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(hubURL, "/")+"/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}

	var out enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode response: %w", err)
	}
	return &out, resp.StatusCode, nil
}
