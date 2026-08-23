package onboard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmhal5l13/acme-agent/config"
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
				Tokens: []string{"existing-token-value"},
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
		HubTLSCertFile: "/etc/acme-spoke/hub-cert.pem",
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

// TestPlan_ExistingSpokeSpokeConfigIncludesAllCerts guards against
// regenerating an existing spoke's config.yaml silently dropping its other
// certificates — SpokeConfigYAML must list every cert the spoke manages,
// not just the one being added in this call.
func TestPlan_ExistingSpokeSpokeConfigIncludesAllCerts(t *testing.T) {
	req := validRequest()
	req.SpokeID = "existing-spoke"
	req.CertName = "second-cert"
	req.Domains = []string{"new.example.com"}

	result, err := Plan(testHubConfig(), req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	if !strings.Contains(result.SpokeConfigYAML, "existing-cert") {
		t.Error("SpokeConfigYAML is missing the spoke's pre-existing certificate — it would silently stop being managed locally")
	}
	if !strings.Contains(result.SpokeConfigYAML, "old.example.com") {
		t.Error("SpokeConfigYAML is missing the pre-existing certificate's domain")
	}
	if !strings.Contains(result.SpokeConfigYAML, "second-cert") {
		t.Error("SpokeConfigYAML is missing the newly added certificate")
	}
	if !strings.Contains(result.SpokeConfigYAML, "new.example.com") {
		t.Error("SpokeConfigYAML is missing the newly added certificate's domain")
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

// TestPlan_DomainDNSProvidersOverrideAppearsInSnippet proves a request
// spanning two DNS providers actually produces a usable domain_dns_providers
// block in the generated hub config snippet - see
// config.SpokeCertConfig.DomainDNSProviders for why one cert's domains can
// need this at all.
func TestPlan_DomainDNSProvidersOverrideAppearsInSnippet(t *testing.T) {
	cfg := testHubConfig()
	cfg.DNSProviders["cloudflare_main"] = config.DNSProviderConfig{Type: "cloudflare"}

	req := validRequest()
	req.Domains = []string{"new.example.com", "new.example.org"}
	req.DomainDNSProviders = map[string]string{"new.example.org": "cloudflare_main"}

	result, err := Plan(cfg, req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, want := range []string{"domain_dns_providers:", "new.example.org: cloudflare_main"} {
		if !strings.Contains(result.HubConfigYAML, want) {
			t.Errorf("hub config YAML missing %q:\n%s", want, result.HubConfigYAML)
		}
	}
}

func TestPlan_DomainDNSProvidersRejectsDomainNotInRequest(t *testing.T) {
	req := validRequest()
	// req.Domains is ["new.example.com"] - this override references a
	// domain that was never added to the request, almost certainly a typo.
	req.DomainDNSProviders = map[string]string{"other.example.org": req.DNSProvider}

	_, err := Plan(testHubConfig(), req)
	if err == nil {
		t.Fatal("expected an error for domain_dns_providers referencing a domain not in Domains, got nil")
	}
}

func TestPlan_DomainDNSProvidersRejectsUnknownProvider(t *testing.T) {
	req := validRequest()
	req.DomainDNSProviders = map[string]string{req.Domains[0]: "does-not-exist"}

	_, err := Plan(testHubConfig(), req)
	if err == nil {
		t.Fatal("expected an error for domain_dns_providers referencing an undefined dns_provider, got nil")
	}
}

func validEnrollmentRequest() EnrollmentRequest {
	return EnrollmentRequest{
		SpokeID:     "new-spoke",
		CertName:    "new-cert",
		Domains:     []string{"new.example.com"},
		DNSProvider: "route53_main",
		HubURL:      "https://192.0.2.10:8443",
	}
}

func TestPlanEnrollment_ValidRequestSucceeds(t *testing.T) {
	plan, err := PlanEnrollment(testHubConfig(), validEnrollmentRequest())
	if err != nil {
		t.Fatalf("PlanEnrollment: %v", err)
	}
	if len(plan.BearerToken) != 64 { // 32 bytes hex-encoded, same as GenerateToken elsewhere
		t.Errorf("got bearer token length %d, want 64", len(plan.BearerToken))
	}
	if len(plan.EnrollmentSecret) != 64 {
		t.Errorf("got enrollment secret length %d, want 64", len(plan.EnrollmentSecret))
	}
	if plan.BearerToken == plan.EnrollmentSecret {
		t.Error("got identical bearer token and enrollment secret, want two independently generated values")
	}
	if plan.HubEnvVarName != "SPOKE_NEW_SPOKE_TOKEN" {
		t.Errorf("got env var name %q, want SPOKE_NEW_SPOKE_TOKEN", plan.HubEnvVarName)
	}
	for _, want := range []string{"new-spoke", "new-cert", "new.example.com", "route53_main", "SPOKE_NEW_SPOKE_TOKEN"} {
		if !strings.Contains(plan.HubConfigYAML, want) {
			t.Errorf("hub config YAML missing %q:\n%s", want, plan.HubConfigYAML)
		}
	}
}

// TestPlanEnrollment_ExistingSpokeErrors is the scope boundary that
// distinguishes PlanEnrollment from Plan: enrolling an already-configured
// spoke isn't this function's job at all, not even to reuse its existing
// token the way Plan does for an additional certificate.
func TestPlanEnrollment_ExistingSpokeErrors(t *testing.T) {
	req := validEnrollmentRequest()
	req.SpokeID = "existing-spoke"

	_, err := PlanEnrollment(testHubConfig(), req)
	if err == nil {
		t.Fatal("expected an error enrolling a spoke that already exists in the hub config, got nil")
	}
}

func TestPlanEnrollment_UnknownDNSProviderErrors(t *testing.T) {
	req := validEnrollmentRequest()
	req.DNSProvider = "does-not-exist"

	_, err := PlanEnrollment(testHubConfig(), req)
	if err == nil {
		t.Fatal("expected an error for a dns_provider not defined in the hub config, got nil")
	}
}

func TestPlanEnrollment_MissingRequiredFieldsError(t *testing.T) {
	base := validEnrollmentRequest()
	cases := []struct {
		name   string
		mutate func(*EnrollmentRequest)
	}{
		{"spoke id", func(r *EnrollmentRequest) { r.SpokeID = "" }},
		{"cert name", func(r *EnrollmentRequest) { r.CertName = "" }},
		{"domains", func(r *EnrollmentRequest) { r.Domains = nil }},
		{"dns provider", func(r *EnrollmentRequest) { r.DNSProvider = "" }},
		{"hub url", func(r *EnrollmentRequest) { r.HubURL = "" }},
	}
	for _, c := range cases {
		req := base
		c.mutate(&req)
		if _, err := PlanEnrollment(testHubConfig(), req); err == nil {
			t.Errorf("missing %s: expected an error, got nil", c.name)
		}
	}
}

func TestPlanEnrollment_DomainDNSProvidersRejectsDomainNotInRequest(t *testing.T) {
	req := validEnrollmentRequest()
	req.DomainDNSProviders = map[string]string{"other.example.org": "route53_main"}

	_, err := PlanEnrollment(testHubConfig(), req)
	if err == nil {
		t.Fatal("expected an error for domain_dns_providers referencing a domain not in Domains, got nil")
	}
}

// TestPlanEnrollment_SuccessiveCallsGenerateDistinctTokens guards against
// a copy-paste mistake reusing the same GenerateToken result for both the
// bearer token and the enrollment secret, or generating either
// non-randomly.
func TestPlanEnrollment_SuccessiveCallsGenerateDistinctTokens(t *testing.T) {
	first, err := PlanEnrollment(testHubConfig(), validEnrollmentRequest())
	if err != nil {
		t.Fatalf("first PlanEnrollment: %v", err)
	}
	second, err := PlanEnrollment(testHubConfig(), validEnrollmentRequest())
	if err != nil {
		t.Fatalf("second PlanEnrollment: %v", err)
	}
	if first.BearerToken == second.BearerToken {
		t.Error("two successive calls generated the identical bearer token")
	}
	if first.EnrollmentSecret == second.EnrollmentSecret {
		t.Error("two successive calls generated the identical enrollment secret")
	}
}

func TestPlanRotation_UnknownSpokeErrors(t *testing.T) {
	_, err := PlanRotation(testHubConfig(), RotationRequest{SpokeID: "no-such-spoke"})
	if err == nil {
		t.Fatal("expected an error for a spoke not defined in the hub config, got nil")
	}
}

func TestPlanRotation_MissingSpokeIDErrors(t *testing.T) {
	_, err := PlanRotation(testHubConfig(), RotationRequest{})
	if err == nil {
		t.Fatal("expected an error for an empty spoke id, got nil")
	}
}

// TestPlanRotation_GeneratesFreshTokenAndDistinctEnvVar proves the two
// properties PlanRotation actually needs to guarantee: the new token is a
// real, freshly generated credential (not a copy of anything already on
// the spoke), and its ${VAR} name doesn't collide with the existing
// token's env var name — see PlanRotation's doc comment on why a plain
// envVarName(spokeID) would be wrong here.
func TestPlanRotation_GeneratesFreshTokenAndDistinctEnvVar(t *testing.T) {
	result, err := PlanRotation(testHubConfig(), RotationRequest{SpokeID: "existing-spoke"})
	if err != nil {
		t.Fatalf("PlanRotation: %v", err)
	}

	if len(result.NewToken) != 64 { // 32 bytes hex-encoded, same as GenerateToken
		t.Errorf("got new token length %d, want 64", len(result.NewToken))
	}
	if result.NewToken == "existing-token-value" {
		t.Error("got the spoke's existing token back, want a freshly generated one")
	}

	wantPrefix := "SPOKE_EXISTING_SPOKE_TOKEN_"
	if !strings.HasPrefix(result.HubEnvVarName, wantPrefix) {
		t.Errorf("got env var name %q, want it to start with %q", result.HubEnvVarName, wantPrefix)
	}
	if result.HubEnvVarName == "SPOKE_EXISTING_SPOKE_TOKEN" {
		t.Error("got the same env var name a fresh onboard would use, want one that can't collide with the existing token's env var")
	}
}

// TestPlanRotation_DoesNotLeakExistingToken guards the specific security
// property in PlanRotation's doc comment: the generated snippet must
// never contain the spoke's actual existing secret value, only
// instructions describing what to add.
func TestPlanRotation_DoesNotLeakExistingToken(t *testing.T) {
	result, err := PlanRotation(testHubConfig(), RotationRequest{SpokeID: "existing-spoke"})
	if err != nil {
		t.Fatalf("PlanRotation: %v", err)
	}
	if strings.Contains(result.HubConfigYAML, "existing-token-value") {
		t.Error("HubConfigYAML leaks the spoke's existing token value, want only instructions to add the new one")
	}
}

// TestPlanRotation_SuccessiveCallsGenerateDistinctTokensAndEnvVars proves
// calling PlanRotation twice in a row (e.g. an operator retrying) doesn't
// hand back the same token or env var name each time.
func TestPlanRotation_SuccessiveCallsGenerateDistinctTokensAndEnvVars(t *testing.T) {
	first, err := PlanRotation(testHubConfig(), RotationRequest{SpokeID: "existing-spoke"})
	if err != nil {
		t.Fatalf("first PlanRotation: %v", err)
	}
	second, err := PlanRotation(testHubConfig(), RotationRequest{SpokeID: "existing-spoke"})
	if err != nil {
		t.Fatalf("second PlanRotation: %v", err)
	}
	if first.NewToken == second.NewToken {
		t.Error("two successive calls generated the identical token")
	}
	if first.HubEnvVarName == second.HubEnvVarName {
		t.Error("two successive calls generated the identical env var name")
	}
}
