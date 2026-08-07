package config

import (
	"fmt"
	"path/filepath"
	"time"
)

// SpokeConfig is the top-level shape of a spoke client's config.yaml. Unlike
// the hub, a spoke never holds DNS provider credentials — DNS-01 challenges
// are relayed through the hub (see internal/hubclient).
type SpokeConfig struct {
	HubURL   string `yaml:"hub_url"`
	HubToken string `yaml:"hub_token"`
	// HubTLSCertFile is the hub's own self-signed certificate (see
	// internal/selfsigned), copied to this spoke out-of-band — cmd/acme-hub
	// logs its SHA-256 fingerprint on first startup for the operator to
	// verify against, the same role an SSH host key fingerprint plays.
	// This spoke pins that exact certificate (internal/hubclient) rather
	// than trusting any certificate authority.
	HubTLSCertFile  string                 `yaml:"hub_tls_cert_file"`
	PollInterval    Duration               `yaml:"poll_interval"`
	RequestTimeout  Duration               `yaml:"request_timeout"` // bounds quick hub calls: due, checkin
	DNS01Timeout    Duration               `yaml:"dns01_timeout"`   // bounds dns01 present/cleanup relay calls, which can block on the hub's DNS provider (e.g. Route53's GetChange wait, ~2min by default)
	RetryBackoff    Duration               `yaml:"retry_backoff"`   // local backoff after a failed issuance attempt
	MaxRetryBackoff Duration               `yaml:"max_retry_backoff"`
	HookTimeout     Duration               `yaml:"hook_timeout"`
	ACME            ACMEConfig             `yaml:"acme"`
	DataDir         string                 `yaml:"data_dir"`
	DBPath          string                 `yaml:"db_path"` // optional; defaults under DataDir
	Certs           []SpokeLocalCertConfig `yaml:"certs"`

	// SkipPropagationCheck disables lego's client-side DNS-01 propagation
	// pre-check (which queries authoritative nameservers directly, bypassing
	// this host's normal resolver). Off by default. Since the spoke never
	// knows which DNS backend the hub actually uses, this is an operator
	// decision based on the spoke's own network (e.g. a firewall that only
	// permits DNS through a specific resolver) or known-fast/reliable
	// propagation, not something inferred automatically. When skipped,
	// Let's Encrypt's own servers still do the real authoritative check.
	SkipPropagationCheck bool `yaml:"skip_propagation_check"`
}

// SpokeLocalCertConfig is one certificate this spoke manages for itself:
// what domains it covers and how to reload the local service that uses it
// once a new certificate is installed.
type SpokeLocalCertConfig struct {
	Name       string   `yaml:"name"`
	Domains    []string `yaml:"domains"`
	ReloadHook string   `yaml:"reload_hook"`
}

const (
	defaultPollInterval    = 15 * time.Minute
	defaultRequestTimeout  = 30 * time.Second
	defaultDNS01Timeout    = 3 * time.Minute // headroom beyond Route53's own ~2min default propagation wait
	defaultRetryBackoff    = time.Hour
	defaultMaxRetryBackoff = 24 * time.Hour
	defaultHookTimeout     = 30 * time.Second
)

// LoadSpokeConfig reads, expands, parses, and validates a spoke's config file.
func LoadSpokeConfig(path string) (*SpokeConfig, error) {
	cfg, err := loadYAML[SpokeConfig](path)
	if err != nil {
		return nil, err
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func (c *SpokeConfig) applyDefaults() {
	if c.DBPath == "" {
		c.DBPath = filepath.Join(c.DataDir, "acme-client.db")
	}
	if c.PollInterval == 0 {
		c.PollInterval = Duration(defaultPollInterval)
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = Duration(defaultRequestTimeout)
	}
	if c.DNS01Timeout == 0 {
		c.DNS01Timeout = Duration(defaultDNS01Timeout)
	}
	if c.RetryBackoff == 0 {
		c.RetryBackoff = Duration(defaultRetryBackoff)
	}
	if c.MaxRetryBackoff == 0 {
		c.MaxRetryBackoff = Duration(defaultMaxRetryBackoff)
	}
	if c.HookTimeout == 0 {
		c.HookTimeout = Duration(defaultHookTimeout)
	}
}

func (c *SpokeConfig) validate() error {
	if c.HubURL == "" {
		return fmt.Errorf("hub_url is required")
	}
	if c.HubToken == "" {
		return fmt.Errorf("hub_token is required")
	}
	if c.HubTLSCertFile == "" {
		return fmt.Errorf("hub_tls_cert_file is required — copy the hub's certificate from its data_dir/tls/cert.pem")
	}
	if c.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}
	if err := c.ACME.validate(); err != nil {
		return err
	}
	if len(c.Certs) == 0 {
		return fmt.Errorf("at least one entry under certs is required")
	}

	seen := make(map[string]bool, len(c.Certs))
	for _, cert := range c.Certs {
		if cert.Name == "" {
			return fmt.Errorf("certs: entry missing name")
		}
		if seen[cert.Name] {
			return fmt.Errorf("certs: duplicate name %q", cert.Name)
		}
		seen[cert.Name] = true

		if len(cert.Domains) == 0 {
			return fmt.Errorf("certs[%s]: at least one domain is required", cert.Name)
		}
	}

	return nil
}
