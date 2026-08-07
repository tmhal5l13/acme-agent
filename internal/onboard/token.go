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
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
