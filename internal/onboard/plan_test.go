package onboard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"acme-agent/config"
)

func testHubConfig() *config.HubConfig {
	return &config.HubConfig{
		ListenAddr: "127.0.0.1:8443",
		DataDir:    "/var/lib/acme-hub",
		DNSProviders: map[string]config.DNSProviderConfig{
			"route53_main": {Type: "route53"},
		},
		Spokes: map[string]config.SpokeEntry{
			"existing-spoke": {
				Token: "existing-token-value",
				Certs: []config.SpokeCertConfig{
					{Name: "existing-cert", Domains: []string{"old.example.com"}, DNSProvider: "route53_main"},
				},
			},
		},
	}
}

func validRequest() Request {
	return Request{
		SpokeID:        "new-spoke",
		CertName:       "new-cert",
		Domains:        []string{"new.example.com"},
		DNSProvider:    "route53_main",
		HubURL:         "https://192.0.2.10:8443",
		HubTLSCertFile: "/etc/acme-client/hub-cert.pem",
		ACMEEmail:      "admin@example.com",
		ACMEEnv:        "staging",
	}
}

func TestPlan_NewSpokeGeneratesFreshToken(t *testing.T) {
	result, err := Plan(testHubConfig(), validRequest())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !result.IsNewSpoke {
		t.Error("got IsNewSpoke=false for a spoke not present in the hub config, want true")
	}
	if len(result.Token) != 64 { // 32 bytes hex-encoded
		t.Errorf("got token length %d, want 64", len(result.Token))
	}
	if result.HubEnvVarName != "SPOKE_NEW_SPOKE_TOKEN" {
		t.Errorf("got env var name %q, want %q", result.HubEnvVarName, "SPOKE_NEW_SPOKE_TOKEN")
	}
}

func TestPlan_ExistingSpokeReusesToken(t *testing.T) {
	req := validRequest()
	req.SpokeID = "existing-spoke"
	req.CertName = "second-cert" // different from the existing cert on this spoke

	result, err := Plan(testHubConfig(), req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if result.IsNewSpoke {
		t.Error("got IsNewSpoke=true for a spoke already present in the hub config, want false")
	}
	if result.Token != "existing-token-value" {
		t.Errorf("got token %q, want the existing spoke's unchanged token %q", result.Token, "existing-token-value")
	}
}

func TestPlan_DuplicateCertNameOnExistingSpokeErrors(t *testing.T) {
	req := validRequest()
	req.SpokeID = "existing-spoke"
	req.CertName = "existing-cert" // already present on this spoke

	_, err := Plan(testHubConfig(), req)
	if err == nil {
		t.Fatal("expected an error for a duplicate cert name on an existing spoke, got nil")
	}
}

func TestPlan_UnknownDNSProviderErrors(t *testing.T) {
	req := validRequest()
	req.DNSProvider = "does-not-exist"

	_, err := Plan(testHubConfig(), req)
	if err == nil {
		t.Fatal("expected an error for a dns_provider not defined in the hub config, got nil")
	}
}

func TestPlan_InvalidACMEEnvironmentErrors(t *testing.T) {
	req := validRequest()
	req.ACMEEnv = "not-a-real-environment"

	_, err := Plan(testHubConfig(), req)
	if err == nil {
		t.Fatal("expected an error for an invalid acme environment, got nil")
	}
}

func TestPlan_MissingRequiredFieldsError(t *testing.T) {
	base := validRequest()
	cases := []struct {
		name   string
		mutate func(*Request)
	}{
		{"spoke id", func(r *Request) { r.SpokeID = "" }},
		{"cert name", func(r *Request) { r.CertName = "" }},
		{"domains", func(r *Request) { r.Domains = nil }},
		{"dns provider", func(r *Request) { r.DNSProvider = "" }},
		{"hub url", func(r *Request) { r.HubURL = "" }},
		{"hub tls cert file", func(r *Request) { r.HubTLSCertFile = "" }},
		{"acme email", func(r *Request) { r.ACMEEmail = "" }},
	}
	for _, c := range cases {
		req := base
		c.mutate(&req)
		if _, err := Plan(testHubConfig(), req); err == nil {
			t.Errorf("missing %s: expected an error, got nil", c.name)
		}
	}
}

// TestPlan_GeneratedSpokeConfigActuallyLoads is the test that matters most:
// it doesn't just check the generated YAML looks plausible, it writes it to
// a file and loads it through the real config.LoadSpokeConfig — proving the
// output is genuinely valid, working configuration, not just text that
// happens to resemble it.
func TestPlan_GeneratedSpokeConfigActuallyLoads(t *testing.T) {
	req := validRequest()
	req.ReloadHook = "systemctl reload nginx"

	result, err := Plan(testHubConfig(), req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	path := filepath.Join(t.TempDir(), "spoke-config.yaml")
	if err := os.WriteFile(path, []byte(result.SpokeConfigYAML), 0o644); err != nil {
		t.Fatalf("write generated config: %v", err)
	}

	t.Setenv("HUB_TOKEN", result.Token)

	loaded, err := config.LoadSpokeConfig(path)
	if err != nil {
		t.Fatalf("generated spoke config failed to load: %v\n--- generated YAML ---\n%s", err, result.SpokeConfigYAML)
	}

	if loaded.HubURL != req.HubURL {
		t.Errorf("got hub_url %q, want %q", loaded.HubURL, req.HubURL)
	}
	if loaded.HubToken != result.Token {
		t.Errorf("got hub_token %q, want the generated token %q", loaded.HubToken, result.Token)
	}
	if len(loaded.Certs) != 1 || loaded.Certs[0].Name != req.CertName {
		t.Errorf("got certs %+v, want one entry named %q", loaded.Certs, req.CertName)
	}
	if loaded.Certs[0].ReloadHook != req.ReloadHook {
		t.Errorf("got reload_hook %q, want %q", loaded.Certs[0].ReloadHook, req.ReloadHook)
	}
}

func TestPlan_HubConfigYAMLContainsExpectedFields(t *testing.T) {
	result, err := Plan(testHubConfig(), validRequest())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, want := range []string{"new-spoke", "new-cert", "new.example.com", "route53_main", "SPOKE_NEW_SPOKE_TOKEN"} {
		if !strings.Contains(result.HubConfigYAML, want) {
			t.Errorf("hub config YAML missing %q:\n%s", want, result.HubConfigYAML)
		}
	}
}
