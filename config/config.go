// Package config loads and validates acme-agent's YAML configuration files
// for both binaries: the hub (cmd/acme-hub) and the spoke client
// (cmd/acme-client).
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration so config fields can be written as plain
// strings in YAML (e.g. "1h", "30s") instead of raw nanosecond integers.
// It satisfies yaml.v3's Unmarshaler interface via UnmarshalYAML below.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler by parsing the YAML scalar as a
// Go duration string (anything time.ParseDuration accepts).
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Duration returns d as a standard time.Duration.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// ACMEConfig selects the ACME CA and identity used for account registration.
type ACMEConfig struct {
	Environment string `yaml:"environment"` // "staging" or "production"
	Email       string `yaml:"email"`
}

func (a ACMEConfig) validate() error {
	if a.Environment != "staging" && a.Environment != "production" {
		return fmt.Errorf("acme.environment must be %q or %q, got %q", "staging", "production", a.Environment)
	}
	if a.Email == "" {
		return fmt.Errorf("acme.email is required")
	}
	return nil
}

// DNSProviderConfig configures one named DNS-01 credential set, held only by
// the hub (spokes never see DNS provider credentials — see
// internal/hubapi). Type selects the internal/dnsprovider factory
// implementation to use; which of the fields below apply depends on Type.
type DNSProviderConfig struct {
	Type string `yaml:"type"`

	// cloudflare
	APIToken string `yaml:"api_token"`

	// route53 (AWS). Deliberately no access key / secret fields: credentials
	// come from the standard AWS SDK credential chain (environment
	// variables, ~/.aws/credentials, or an IAM role) rather than this file,
	// per AWS's own guidance against long-lived keys in application config.
	// HostedZoneID and Region are optional overrides.
	HostedZoneID string `yaml:"hosted_zone_id"`
	Region       string `yaml:"region"`

	// godaddy
	APIKey    string `yaml:"api_key"`
	APISecret string `yaml:"api_secret"`

	// pdns (self-hosted PowerDNS). APIURL is required (e.g.
	// "http://127.0.0.1:8081"); ServerName is optional and defaults to
	// "localhost", PowerDNS's own default virtual server ID.
	APIURL     string `yaml:"api_url"`
	ServerName string `yaml:"server_name"`
}

// loadYAML reads path, expands ${VAR} references against the process
// environment, and unmarshals the result into a fresh T. Shared by
// LoadHubConfig and LoadSpokeConfig so secret-interpolation behavior (no
// secrets ever need to be written into the file itself) stays identical
// across both.
func loadYAML[T any](path string) (*T, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	expanded := os.ExpandEnv(string(raw))

	var cfg T
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	return &cfg, nil
}
