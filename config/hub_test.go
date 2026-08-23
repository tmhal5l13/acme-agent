package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// validHubConfig returns a HubConfig that passes validate() unmodified,
// so each test only needs to change the one field it's actually testing.
func validHubConfig() *HubConfig {
	return &HubConfig{
		ListenAddr: "127.0.0.1:8443",
		DataDir:    "/var/lib/acme-hub",
	}
}

func TestHubConfig_ValidConfigPasses(t *testing.T) {
	if err := validHubConfig().validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHubConfig_RequiresListenAddr(t *testing.T) {
	cfg := validHubConfig()
	cfg.ListenAddr = ""
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for empty listen_addr, got nil")
	}
}

func TestHubConfig_RequiresDataDir(t *testing.T) {
	cfg := validHubConfig()
	cfg.DataDir = ""
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for empty data_dir, got nil")
	}
}

// TestHubConfig_RejectsLegacySpokesKey and _RejectsLegacyDNSProvidersKey
// prove a config file still carrying the pre-cutover spokes:/dns_providers:
// keys is rejected with a clear error pointing at --import-config, rather
// than silently loading with that desired state quietly ignored - plain
// yaml.Unmarshal on its own would do exactly that silent-ignore, since it
// drops any key with no matching struct field. Every other spoke/DNS-provider
// validation rule that used to live here (unique tokens, path-safe cert
// names, well-formed domains, dns_provider references) now lives in
// internal/hubstore - see that package's own tests for the same coverage,
// now enforced where it actually runs.
func TestHubConfig_RejectsLegacySpokesKey(t *testing.T) {
	var cfg HubConfig
	if err := yaml.Unmarshal([]byte(`
listen_addr: "127.0.0.1:8443"
data_dir: /var/lib/acme-hub
spokes:
  spoke-a:
    tokens: [token-a]
    certs:
      - name: cert-a
        domains: [example.com]
        dns_provider: route53
`), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected an error for a config file still carrying spokes:, got nil")
	}
	if !strings.Contains(err.Error(), "--import-config") {
		t.Errorf("error %q does not mention --import-config", err.Error())
	}
}

func TestHubConfig_RejectsLegacyDNSProvidersKey(t *testing.T) {
	var cfg HubConfig
	if err := yaml.Unmarshal([]byte(`
listen_addr: "127.0.0.1:8443"
data_dir: /var/lib/acme-hub
dns_providers:
  route53_main:
    type: route53
`), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected an error for a config file still carrying dns_providers:, got nil")
	}
	if !strings.Contains(err.Error(), "--import-config") {
		t.Errorf("error %q does not mention --import-config", err.Error())
	}
}

// TestHubConfig_RejectsNegativeRenewBefore proves ACMEDefaultsConfig's
// Duration fields go through the same negative-Duration rejection as
// everything else - see Duration.UnmarshalYAML and TestDuration_RejectsNegative
// for the underlying mechanism; this is the integration point that would
// have missed it if RenewBefore were somehow parsed differently.
func TestHubConfig_RejectsNegativeRenewBefore(t *testing.T) {
	var cfg HubConfig
	err := yaml.Unmarshal([]byte(`
listen_addr: "127.0.0.1:8443"
data_dir: /var/lib/acme-hub
acme_defaults:
  renew_before: "-24h"
`), &cfg)
	if err == nil {
		t.Error("expected an error parsing a negative renew_before, got nil")
	}
}
