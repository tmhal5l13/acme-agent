package onboard

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateToken returns a fresh, cryptographically random bearer token: 32
// bytes (256 bits) of entropy, hex-encoded so it drops into YAML or an env
// file without any quoting/escaping concerns.
func GenerateToken() (string, error) {
	return randomHex(32)
}

// randomHex returns n random bytes, hex-encoded. Shared by GenerateToken
// (n=32, a real security credential) and PlanRotation's env-var-suffix
// generator (a much smaller n - it only needs to be unique enough to
// avoid a naming collision, not cryptographically unguessable, but the
// same crypto/rand source is just as easy to use for it as anything
// weaker would be).
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}
