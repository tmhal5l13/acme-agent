// Package enrolltoken is the opaque, self-contained token
// `acme-hub --generate-token` prints and `acme-spoke --load-token`
// decodes — one string an operator copies from the hub to a new spoke,
// carrying everything needed to find the hub, verify it cryptographically
// on first contact, and redeem a one-time enrollment secret against it
// (see internal/hubapi's POST /v1/enroll and internal/hubstore's
// enrollment_tokens table).
package enrolltoken

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Token is encoded as base64(json), not split across several flags a
// spoke's config.yaml, so an operator only ever has to copy one string.
type Token struct {
	// HubURL is where the spoke dials to reach the hub - the same value
	// it'll write into its own generated config.yaml as hub_url.
	HubURL string `json:"hub_url"`

	// Fingerprint is the hub's TLS certificate's SHA-256 fingerprint (see
	// selfsigned.Fingerprint), computed at token-generation time. The
	// spoke checks the certificate presented on its first TLS handshake
	// against this before trusting anything - real cryptographic
	// verification via out-of-band provenance (the operator who ran
	// --generate-token), not trust-on-first-use.
	Fingerprint string `json:"fingerprint"`

	// Secret is the one-time enrollment secret redeemed against
	// POST /v1/enroll.
	Secret string `json:"secret"`
}

// Encode returns t as one opaque, copy-pasteable string.
func (t Token) Encode() (string, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("encode enrollment token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// Decode parses a string produced by Token.Encode.
func Decode(s string) (Token, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Token{}, fmt.Errorf("decode enrollment token: %w", err)
	}
	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return Token{}, fmt.Errorf("decode enrollment token: %w", err)
	}
	if t.HubURL == "" || t.Fingerprint == "" || t.Secret == "" {
		return Token{}, fmt.Errorf("decode enrollment token: missing hub_url, fingerprint, or secret")
	}
	return t, nil
}
