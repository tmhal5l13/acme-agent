package config

import (
	"fmt"
	"path/filepath"
	"time"
)

// HubConfig is the top-level shape of the hub's config.yaml. Domains, DNS
// provider assignment, and renewal policy are desired state and live here;
// internal/hubstore holds only what spokes have reported (observed state).
type HubConfig struct {
	ListenAddr   string                       `yaml:"listen_addr"` // prefer a private/internal interface over a public one where your network allows it — see TLS below for why this isn't the primary security boundary
	DataDir      string                       `yaml:"data_dir"`
	DBPath       string                       `yaml:"db_path"` // optional; defaults under DataDir
	ACMEDefaults ACMEDefaultsConfig           `yaml:"acme_defaults"`
	DNSProviders map[string]DNSProviderConfig `yaml:"dns_providers"`
	Spokes       map[string]SpokeEntry        `yaml:"spokes"`

	// TLSCertFile/TLSKeyFile locate the hub's TLS certificate and key.
	// Both optional — if either is left blank, they default under DataDir
	// and, if no certificate exists there yet, one is self-signed on
	// first startup (see internal/selfsigned and cmd/acme-hub). Spokes
	// trust this exact certificate directly (internal/hubclient) rather
	// than a certificate authority, since the hub typically has no public
	// DNS name for a real CA to issue against.
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`

	// TLSHost is the address spokes actually dial — embedded as the
	// self-signed certificate's SAN (see internal/selfsigned), since Go's
	// TLS client verifies the presented certificate against the address it
	// dialed, not just whether the certificate is trusted. Optional —
	// defaults to ListenAddr's host portion, which is correct whenever
	// ListenAddr is itself a specific, dialable interface. It's only
	// required when ListenAddr is a wildcard bind (e.g. "0.0.0.0:8443",
	// listening on every interface) while spokes reach the hub through one
	// specific hostname or IP — that hostname belongs here instead, or the
	// generated certificate ends up issued for the meaningless identity
	// "0.0.0.0" and every spoke's TLS handshake fails.
	TLSHost string `yaml:"tls_host"`

	// NotifyHook is an optional shell command run when a certificate's
	// status transitions to "failed" (alert) or from "failed" back to
	// "active" (resolved) — see internal/hubapi's checkin handler for the
	// exact trigger. Empty disables notifications entirely. Invoked the
	// same way reload_hook is (internal/hook), with context passed via
	// environment variables (ACME_SPOKE, ACME_CERT, ACME_STATUS,
	// ACME_PREVIOUS_STATUS, ACME_ERROR, ACME_NOT_AFTER) rather than a
	// hardcoded notification backend, so the operator can point it at
	// mail, a webhook, ntfy.sh, or anything else.
	NotifyHook    string   `yaml:"notify_hook"`
	NotifyTimeout Duration `yaml:"notify_timeout"`
}

// ACMEDefaultsConfig holds renewal policy defaults, overridable per cert via
// SpokeCertConfig.RenewBefore.
type ACMEDefaultsConfig struct {
	RenewBefore Duration `yaml:"renew_before"`

	// RenewalJitter staggers exactly when each certificate starts being
	// considered due, so a fleet of certificates issued around the same
	// time doesn't all converge on renewing at the identical moment —
	// the same "randomized renewal" practice Let's Encrypt's own client
	// list requires, applied here at the hub (the scheduling authority)
	// rather than per-spoke. Each certificate gets a jitter amount in
	// [0, RenewalJitter) that's stable across checks (deterministically
	// derived from spoke+cert name, not re-rolled every request — an
	// unstable jitter would make "due" flip-flop between polls) and only
	// ever makes a certificate due *earlier*, never later — it can't cut
	// into the safety margin RenewBefore was set to guarantee.
	//
	// Left unset (zero), it defaults to defaultRenewalJitter like every
	// other Duration field in this config — there's deliberately no way
	// to fully disable it by setting 0, the same limitation every other
	// field here already has (this project treats the zero value as
	// "unset", not "explicitly disabled"). To make jitter negligible,
	// set a very small nonzero value instead.
	RenewalJitter Duration `yaml:"renewal_jitter"`
}

// SpokeEntry is one spoke's identity (its bearer token) and the certificates
// it's authorized to request/renew. The token is what a spoke presents on
// every API call; the hub looks up which spoke (and therefore which certs
// and domains) a request is authorized to act on purely from this map — a
// spoke can never request a DNS-01 change for a domain outside its own
// Certs list.
type SpokeEntry struct {
	Token string            `yaml:"token"`
	Certs []SpokeCertConfig `yaml:"certs"`
}

// SpokeCertConfig is one certificate a spoke is authorized to manage.
type SpokeCertConfig struct {
	Name        string   `yaml:"name"`
	Domains     []string `yaml:"domains"`
	DNSProvider string   `yaml:"dns_provider"`
	RenewBefore Duration `yaml:"renew_before"` // optional; 0 means "use ACMEDefaults.RenewBefore"
}

const (
	defaultHubRenewBefore = 30 * 24 * time.Hour
	defaultNotifyTimeout  = 30 * time.Second
	defaultRenewalJitter  = 48 * time.Hour
)

// LoadHubConfig reads, expands, parses, and validates the hub's config file.
func LoadHubConfig(path string) (*HubConfig, error) {
	cfg, err := loadYAML[HubConfig](path)
	if err != nil {
		return nil, err
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func (c *HubConfig) applyDefaults() {
	if c.DBPath == "" {
		c.DBPath = filepath.Join(c.DataDir, "acme-hub.db")
	}
	if c.ACMEDefaults.RenewBefore == 0 {
		c.ACMEDefaults.RenewBefore = Duration(defaultHubRenewBefore)
	}
	if c.ACMEDefaults.RenewalJitter == 0 {
		c.ACMEDefaults.RenewalJitter = Duration(defaultRenewalJitter)
	}
	if c.NotifyTimeout == 0 {
		c.NotifyTimeout = Duration(defaultNotifyTimeout)
	}
	if c.TLSCertFile == "" {
		c.TLSCertFile = filepath.Join(c.DataDir, "tls", "cert.pem")
	}
	if c.TLSKeyFile == "" {
		c.TLSKeyFile = filepath.Join(c.DataDir, "tls", "key.pem")
	}
}

func (c *HubConfig) validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	if c.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}
	// No "at least one spoke" requirement: a freshly bootstrapped hub with
	// zero spokes yet is a normal state (about to receive its first one via
	// cmd/acme-onboard), not a misconfiguration — it just means the hub
	// currently serves no one.

	seenTokens := make(map[string]string, len(c.Spokes)) // token -> spoke id, to catch accidental reuse
	for spokeID, spoke := range c.Spokes {
		if spoke.Token == "" {
			return fmt.Errorf("spokes[%s]: token is required", spokeID)
		}
		if other, ok := seenTokens[spoke.Token]; ok {
			return fmt.Errorf("spokes[%s]: token is also used by spokes[%s] — tokens must be unique, they're how a request is identified", spokeID, other)
		}
		seenTokens[spoke.Token] = spokeID

		if len(spoke.Certs) == 0 {
			return fmt.Errorf("spokes[%s]: at least one entry under certs is required", spokeID)
		}

		seenNames := make(map[string]bool, len(spoke.Certs))
		for _, cert := range spoke.Certs {
			if err := validateCertName(cert.Name); err != nil {
				return fmt.Errorf("spokes[%s]: %w", spokeID, err)
			}
			if seenNames[cert.Name] {
				return fmt.Errorf("spokes[%s]: duplicate cert name %q", spokeID, cert.Name)
			}
			seenNames[cert.Name] = true

			if len(cert.Domains) == 0 {
				return fmt.Errorf("spokes[%s].certs[%s]: at least one domain is required", spokeID, cert.Name)
			}
			for _, d := range cert.Domains {
				if err := validateDomain(d); err != nil {
					return fmt.Errorf("spokes[%s].certs[%s]: %w", spokeID, cert.Name, err)
				}
			}
			if _, ok := c.DNSProviders[cert.DNSProvider]; !ok {
				return fmt.Errorf("spokes[%s].certs[%s]: dns_provider %q is not defined under dns_providers", spokeID, cert.Name, cert.DNSProvider)
			}
		}
	}

	return nil
}
