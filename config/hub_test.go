package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// validHubConfig returns a HubConfig that passes validate() unmodified,
// so each test only needs to change the one field it's actually testing.
func validHubConfig() *HubConfig {
	return &HubConfig{
		ListenAddr: "127.0.0.1:8443",
		DataDir:    "/var/lib/acme-hub",
		DNSProviders: map[string]DNSProviderConfig{
			"route53": {Type: "route53"},
		},
		Spokes: map[string]SpokeEntry{
			"spoke-a": {
				Tokens: []string{"token-a"},
				Certs: []SpokeCertConfig{
					{Name: "cert-a", Domains: []string{"example.com"}, DNSProvider: "route53"},
				},
			},
		},
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

func TestHubConfig_NoSpokesIsValid(t *testing.T) {
	cfg := validHubConfig()
	cfg.Spokes = nil
	if err := cfg.validate(); err != nil {
		t.Errorf("a freshly bootstrapped hub with zero spokes should be valid, got: %v", err)
	}
}

func TestHubConfig_RejectsDuplicateTokensAcrossSpokes(t *testing.T) {
	cfg := validHubConfig()
	cfg.Spokes["spoke-b"] = SpokeEntry{
		Tokens: []string{"token-a"}, // same as spoke-a's
		Certs:  []SpokeCertConfig{{Name: "cert-b", Domains: []string{"other.example.com"}, DNSProvider: "route53"}},
	}
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for a token reused across spokes, got nil")
	}
}

// TestHubConfig_MultipleTokensPerSpokeIsValid proves a spoke can list more
// than one token under tokens — the state a rotation grace period leaves it
// in (see SpokeEntry's doc comment and internal/onboard.PlanRotation): both
// an old and a new token valid for the same spoke simultaneously.
func TestHubConfig_MultipleTokensPerSpokeIsValid(t *testing.T) {
	cfg := validHubConfig()
	spoke := cfg.Spokes["spoke-a"]
	spoke.Tokens = []string{"token-a", "token-a-new"}
	cfg.Spokes["spoke-a"] = spoke
	if err := cfg.validate(); err != nil {
		t.Errorf("unexpected error for a spoke with two distinct tokens: %v", err)
	}
}

// TestHubConfig_RejectsDuplicateTokensWithinSameSpoke guards the same
// uniqueness check as TestHubConfig_RejectsDuplicateTokensAcrossSpokes, but
// for the same spoke listing the identical token twice under its own
// tokens list.
func TestHubConfig_RejectsDuplicateTokensWithinSameSpoke(t *testing.T) {
	cfg := validHubConfig()
	spoke := cfg.Spokes["spoke-a"]
	spoke.Tokens = []string{"token-a", "token-a"}
	cfg.Spokes["spoke-a"] = spoke
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for a token repeated within one spoke's own tokens list, got nil")
	}
}

func TestHubConfig_RejectsEmptyTokenEntry(t *testing.T) {
	cfg := validHubConfig()
	spoke := cfg.Spokes["spoke-a"]
	spoke.Tokens = []string{"token-a", ""}
	cfg.Spokes["spoke-a"] = spoke
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for an empty entry in tokens, got nil")
	}
}

func TestHubConfig_RejectsNoTokens(t *testing.T) {
	cfg := validHubConfig()
	spoke := cfg.Spokes["spoke-a"]
	spoke.Tokens = nil
	cfg.Spokes["spoke-a"] = spoke
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for a spoke with no tokens at all, got nil")
	}
}

func TestHubConfig_RejectsUnknownDNSProvider(t *testing.T) {
	cfg := validHubConfig()
	spoke := cfg.Spokes["spoke-a"]
	spoke.Certs[0].DNSProvider = "does-not-exist"
	cfg.Spokes["spoke-a"] = spoke
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for a dns_provider not defined under dns_providers, got nil")
	}
}

// TestHubConfig_CertNameSafety is the actual proof of the path-traversal
// fix: internal/spokeagent.ProcessCert does
// filepath.Join(dataDir, "certs", cert.Name) unguarded, so a name like
// "../../etc" reaching that call would write outside the intended certs
// directory.
func TestHubConfig_CertNameSafety(t *testing.T) {
	cases := []struct {
		name    string
		wantErr bool
	}{
		{"my-cert", false},
		{"radius-cert", false},
		{"", true},
		{".", true},
		{"..", true},
		{"../../etc/passwd", true},
		{"a/b", true},
	}
	for _, c := range cases {
		cfg := validHubConfig()
		spoke := cfg.Spokes["spoke-a"]
		spoke.Certs[0].Name = c.name
		cfg.Spokes["spoke-a"] = spoke

		err := cfg.validate()
		if c.wantErr && err == nil {
			t.Errorf("name %q: expected an error, got nil", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("name %q: unexpected error: %v", c.name, err)
		}
	}
}

func TestHubConfig_RejectsMalformedDomain(t *testing.T) {
	cfg := validHubConfig()
	spoke := cfg.Spokes["spoke-a"]
	spoke.Certs[0].Domains = []string{""}
	cfg.Spokes["spoke-a"] = spoke
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for an empty domain string, got nil")
	}
}

func TestHubConfig_AllowsWildcardDomain(t *testing.T) {
	cfg := validHubConfig()
	spoke := cfg.Spokes["spoke-a"]
	spoke.Certs[0].Domains = []string{"example.com", "*.example.com"}
	cfg.Spokes["spoke-a"] = spoke
	if err := cfg.validate(); err != nil {
		t.Errorf("unexpected error for a wildcard domain: %v", err)
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
