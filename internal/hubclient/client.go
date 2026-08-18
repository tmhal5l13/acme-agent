// Package hubclient is a spoke's client for the hub's HTTP API: asking
// whether a certificate is due, reporting the outcome of an attempt, and
// relaying DNS-01 challenges through the hub (see provider.go).
package hubclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client talks to the hub's API on behalf of one spoke, identified by a
// single bearer token that authorizes it for whichever certificates the
// hub's config grants it.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New builds a Client that trusts exactly caCertFile's certificate — the
// hub's own self-signed certificate, copied to this spoke out-of-band —
// rather than any certificate authority. The hub typically has no public
// DNS name for a real CA to issue against, so pinning the specific
// certificate is the standard approach here, the same role an SSH
// known_hosts entry plays; it is emphatically not the same thing as
// skipping verification (InsecureSkipVerify), which this does not use.
//
// It applies no request timeout of its own — callers bound each request
// via the context they pass to do (see Due, Checkin, and DNS01Provider),
// since different calls need very different bounds: due and checkin are
// quick, but a dns01 present/cleanup call can block on the hub's DNS
// provider (e.g. Route53's own ~2-minute propagation wait) far longer than
// a "normal" API call should ever take.
func New(baseURL, token, caCertFile string) (*Client, error) {
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("read hub tls cert file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("no certificate found in %s", caCertFile)
	}

	// MinVersion is pinned to TLS 1.3, not left at Go's own default: both
	// ends of this connection are always this project's own binaries (the
	// hub self-signs its own certificate specifically for this pinned
	// relationship - see New's doc comment), so there's no third-party
	// TLS 1.2-only peer to stay compatible with, and pinning removes any
	// dependency on Go's default minimum version staying where it is
	// across future Go upgrades.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
	}

	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		http:    &http.Client{Transport: transport},
	}, nil
}

// do sends one request, JSON-encoding reqBody if non-nil and JSON-decoding
// the response into respBody if non-nil. Any non-2xx status becomes an
// error carrying the hub's response body, since that's where hubapi puts
// its (often actionable, e.g. "domain not authorized") error messages.
func (c *Client) do(ctx context.Context, method, path string, reqBody, respBody any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(b)))
	}

	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// Due asks the hub whether certName is due for renewal — the hub is the
// scheduling authority, deciding based on what the spoke last reported via
// Checkin against that certificate's renewal policy.
func (c *Client) Due(ctx context.Context, certName string) (bool, error) {
	var resp struct {
		Due bool `json:"due"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/certs/"+certName+"/due", nil, &resp); err != nil {
		return false, err
	}
	return resp.Due, nil
}

// CheckinRequest reports the outcome of an issuance/renewal attempt.
type CheckinRequest struct {
	Domains   []string  `json:"domains"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Serial    string    `json:"serial"`
	Status    string    `json:"status"` // "active" or "failed"
	Error     string    `json:"error"`
	// ConsecutiveFailures is only meaningful when Status is "failed" - the
	// spoke's own local failure-streak count for this certificate (see
	// internal/store.CertState.ConsecutiveFailures), so the hub can tell a
	// cert's first failed attempt from its fifteenth.
	ConsecutiveFailures int `json:"consecutive_failures"`
}

// Checkin reports req to the hub for certName.
func (c *Client) Checkin(ctx context.Context, certName string, req CheckinRequest) error {
	return c.do(ctx, http.MethodPost, "/v1/certs/"+certName+"/checkin", req, nil)
}
