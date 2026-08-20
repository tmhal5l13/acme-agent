package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// validSpokeConfig returns a SpokeConfig that passes validate() unmodified,
// so each test only needs to change the one field it's actually testing.
func validSpokeConfig() *SpokeConfig {
	return &SpokeConfig{
		HubURL:         "https://192.0.2.10:8443",
		HubToken:       "hub-token",
		HubTLSCertFile: "/etc/acme-spoke/hub-cert.pem",
		DataDir:        "/var/lib/acme-spoke",
		ACME:           ACMEConfig{Environment: "staging"},
		Certs: []SpokeLocalCertConfig{
			{Name: "radius-cert", Domains: []string{"radius.example.com"}},
		},
	}
}

func TestSpokeConfig_ValidConfigPasses(t *testing.T) {
	if err := validSpokeConfig().validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSpokeConfig_RequiresHubURL(t *testing.T) {
	cfg := validSpokeConfig()
	cfg.HubURL = ""
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for empty hub_url, got nil")
	}
}

func TestSpokeConfig_RequiresHubToken(t *testing.T) {
	cfg := validSpokeConfig()
	cfg.HubToken = ""
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for empty hub_token, got nil")
	}
}

func TestSpokeConfig_RequiresHubTLSCertFile(t *testing.T) {
	cfg := validSpokeConfig()
	cfg.HubTLSCertFile = ""
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for empty hub_tls_cert_file, got nil")
	}
}

func TestSpokeConfig_RequiresAtLeastOneCert(t *testing.T) {
	cfg := validSpokeConfig()
	cfg.Certs = nil
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for zero certs, got nil")
	}
}

func TestSpokeConfig_RejectsDuplicateCertNames(t *testing.T) {
	cfg := validSpokeConfig()
	cfg.Certs = append(cfg.Certs, SpokeLocalCertConfig{Name: "radius-cert", Domains: []string{"other.example.com"}})
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for a duplicate cert name, got nil")
	}
}

// TestSpokeConfig_CertNameSafety is this config's version of the same
// path-traversal fix hub_test.go proves - this is actually the more
// directly relevant one, since it's this exact config's cert.Name that
// internal/spokeagent.ProcessCert (spoke-local, unlike the hub) joins
// straight into a filesystem path.
func TestSpokeConfig_CertNameSafety(t *testing.T) {
	cases := []struct {
		name    string
		wantErr bool
	}{
		{"radius-cert", false},
		{"", true},
		{".", true},
		{"..", true},
		{"../../etc/passwd", true},
		{"a/b", true},
	}
	for _, c := range cases {
		cfg := validSpokeConfig()
		cfg.Certs[0].Name = c.name

		err := cfg.validate()
		if c.wantErr && err == nil {
			t.Errorf("name %q: expected an error, got nil", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("name %q: unexpected error: %v", c.name, err)
		}
	}
}

func TestSpokeConfig_RejectsMalformedDomain(t *testing.T) {
	cfg := validSpokeConfig()
	cfg.Certs[0].Domains = []string{" "}
	if err := cfg.validate(); err == nil {
		t.Error("expected an error for a whitespace-only domain, got nil")
	}
}

func TestSpokeConfig_AllowsWildcardDomain(t *testing.T) {
	cfg := validSpokeConfig()
	cfg.Certs[0].Domains = []string{"example.com", "*.example.com"}
	if err := cfg.validate(); err != nil {
		t.Errorf("unexpected error for a wildcard domain: %v", err)
	}
}

// TestSpokeConfig_RejectsNegativePollInterval is this config's version of
// hub_test.go's negative-Duration integration check.
func TestSpokeConfig_RejectsNegativePollInterval(t *testing.T) {
	var cfg SpokeConfig
	err := yaml.Unmarshal([]byte(`
hub_url: "https://192.0.2.10:8443"
hub_token: "hub-token"
hub_tls_cert_file: /etc/acme-spoke/hub-cert.pem
data_dir: /var/lib/acme-spoke
poll_interval: "-15m"
`), &cfg)
	if err == nil {
		t.Error("expected an error parsing a negative poll_interval, got nil")
	}
}

// TestLoadSpokeConfig_ExampleFileStillLoads mirrors config_test.go's hub
// counterpart - deploy/spoke-config.example.yaml already used only the
// braced ${VAR} form.
func TestLoadSpokeConfig_ExampleFileStillLoads(t *testing.T) {
	t.Setenv("HUB_TOKEN", "test-value")

	path := repoPath(t, "deploy", "spoke-config.example.yaml")
	if _, err := LoadSpokeConfig(path); err != nil {
		t.Fatalf("LoadSpokeConfig(%s): %v", path, err)
	}
}
