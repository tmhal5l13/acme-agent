// Package selfsigned generates a self-signed TLS certificate for the hub's
// API. It exists so the hub doesn't depend on the operator already having a
// CA, a public cert, or any particular private-network setup: the spoke
// pins this exact certificate instead of trusting a certificate authority
// (see internal/hubclient), which is the standard approach for securing an
// internal-only service that has no public DNS name of its own.
package selfsigned

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

const validity = 10 * 365 * 24 * time.Hour

// EnsureCert generates a self-signed ECDSA P-256 certificate and key at
// certPath/keyPath if they don't already both exist; if they do, it leaves
// them untouched. That idempotency matters: regenerating on every restart
// would invalidate every spoke's pinned copy of the old certificate.
//
// host is the address spokes will actually connect to (typically the same
// host portion as HubConfig.ListenAddr) — it's embedded as the
// certificate's SAN (as an IP or a DNS name, whichever host parses as),
// since Go's TLS client verifies the presented certificate's SAN against
// the address it dialed, not just whether the certificate is trusted.
func EnsureCert(certPath, keyPath, host string) error {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if certErr == nil && keyErr == nil {
		return nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	return nil
}
