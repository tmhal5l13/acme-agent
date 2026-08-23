package onboard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
)

// testStore returns a real temp-file hubstore.Store seeded with one DNS
// provider (route53_main) and one existing spoke (existing-spoke, token
// existing-token-value, one cert existing-cert/old.example.com) - the
// database-backed equivalent of the old testHubConfig() fixture.
func testStore(t *testing.T) *hubstore.Store {
	t.Helper()
	st, err := hubstore.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if err := st.UpsertDNSProvider("route53_main", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("seed dns provider: %v", err)
	}
	if err := st.CreateSpoke("existing-spoke", "existing-token-value"); err != nil {
		t.Fatalf("seed existing spoke: %v", err)
	}
	if err := st.UpsertSpokeCert("existing-spoke", config.SpokeCertConfig{
		Name: "existing-cert", Domains: []string{"old.example.com"}, DNSProvider: "route53_main",
	}); err != nil {
		t.Fatalf("seed existing cert: %v", err)
	}
	return st
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

func TestPlan_NewSpokeCreatesSpokeAndCert(t *testing.T) {
	st := testStore(t)
	result, err := Plan(st, validRequest())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !result.IsNewSpoke {
		t.Error("got IsNewSpoke=false for a spoke that didn't exist yet, want true")
	}
	if len(result.Token) != 64 { // 32 bytes hex-encoded
		t.Errorf("got token length %d, want 64", len(result.Token))
	}

	got, err := st.GetSpoke("new-spoke")
	if err != nil {
		t.Fatalf("GetSpoke after Plan: %v", err)
	}
	if len(got.Tokens) != 1 || got.Tokens[0] != result.Token {
		t.Errorf("got tokens %v, want exactly the returned token", got.Tokens)
	}
	if len(got.Certs) != 1 || got.Certs[0].Name != "new-cert" {
		t.Errorf("got certs %+v, want one new-cert", got.Certs)
	}
}

func TestPlan_ExistingSpokeReusesToken(t *testing.T) {
	st := testStore(t)
	req := validRequest()
	req.SpokeID = "existing-spoke"
	req.CertName = "second-cert" // different from the existing cert on this spoke

	result, err := Plan(st, req)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if result.IsNewSpoke {
		t.Error("got IsNewSpoke=true for a spoke that already existed, want false")
	}
	if result.Token != "existing-token-value" {
		t.Errorf("got token %q, want the existing spoke's unchanged token %q", result.Token, "existing-token-value")
	}

	got, err := st.GetSpoke("existing-spoke")
	if err != nil {
		t.Fatalf("GetSpoke after Plan: %v", err)
	}
	if len(got.Certs) != 2 {
		t.Errorf("got %d certs, want 2 (the pre-existing one plus the new one)", len(got.Certs))
	}
}

// TestPlan_ExistingSpokeSpokeConfigIncludesAllCerts guards against
// regenerating an existing spoke's config.yaml silently dropping its other
// certificates — SpokeConfigYAML must list every cert the spoke manages,
// not just the one being added in this call.
func TestPlan_ExistingSpokeSpokeConfigIncludesAllCerts(t *testing.T) {
	st := testStore(t)
	req := validRequest()
	req.SpokeID = "existing-spoke"
	req.CertName = "second-cert"
	req.Domains = []string{"new.example.com"}

	result, err := Plan(st, req)
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
	st := testStore(t)
	req := validRequest()
	req.SpokeID = "existing-spoke"
	req.CertName = "existing-cert" // already present on this spoke

	_, err := Plan(st, req)
	if err == nil {
		t.Fatal("expected an error for a duplicate cert name on an existing spoke, got nil")
	}
}

func TestPlan_RejectsUnknownDNSProvider(t *testing.T) {
	st := testStore(t)
	req := validRequest()
	req.DNSProvider = "does-not-exist"

	_, err := Plan(st, req)
	if err == nil {
		t.Fatal("expected an error for a dns_provider that doesn't exist on the hub, got nil")
	}
}

func TestPlan_InvalidACMEEnvironmentErrors(t *testing.T) {
	st := testStore(t)
	req := validRequest()
	req.ACMEEnv = "not-a-real-environment"

	_, err := Plan(st, req)
	if err == nil {
		t.Fatal("expected an error for an invalid acme environment, got nil")
	}
}

func TestPlan_MissingRequiredFieldsError(t *testing.T) {
	st := testStore(t)
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
		if _, err := Plan(st, req); err == nil {
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
	st := testStore(t)
	req := validRequest()
	req.ReloadHook = "systemctl reload nginx"

	result, err := Plan(st, req)
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

// TestPlan_DomainDNSProvidersOverrideIsStored proves a request spanning
// two DNS providers actually persists a usable domain_dns_providers
// assignment - see config.SpokeCertConfig.DomainDNSProviders for why one
// cert's domains can need this at all.
func TestPlan_DomainDNSProvidersOverrideIsStored(t *testing.T) {
	st := testStore(t)
	if err := st.UpsertDNSProvider("cloudflare_main", config.DNSProviderConfig{Type: "cloudflare"}); err != nil {
		t.Fatalf("seed cloudflare_main: %v", err)
	}

	req := validRequest()
	req.Domains = []string{"new.example.com", "new.example.org"}
	req.DomainDNSProviders = map[string]string{"new.example.org": "cloudflare_main"}

	if _, err := Plan(st, req); err != nil {
		t.Fatalf("Plan: %v", err)
	}

	got, err := st.GetSpoke("new-spoke")
	if err != nil {
		t.Fatalf("GetSpoke: %v", err)
	}
	if len(got.Certs) != 1 || got.Certs[0].DomainDNSProviders["new.example.org"] != "cloudflare_main" {
		t.Errorf("got certs %+v, want the domain_dns_providers override to have persisted", got.Certs)
	}
}

func TestPlan_DomainDNSProvidersRejectsDomainNotInRequest(t *testing.T) {
	st := testStore(t)
	req := validRequest()
	// req.Domains is ["new.example.com"] - this override references a
	// domain that was never added to the request, almost certainly a typo.
	req.DomainDNSProviders = map[string]string{"other.example.org": req.DNSProvider}

	_, err := Plan(st, req)
	if err == nil {
		t.Fatal("expected an error for domain_dns_providers referencing a domain not in Domains, got nil")
	}
}

func TestPlan_DomainDNSProvidersRejectsUnknownProvider(t *testing.T) {
	st := testStore(t)
	req := validRequest()
	req.DomainDNSProviders = map[string]string{req.Domains[0]: "does-not-exist"}

	_, err := Plan(st, req)
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
	st := testStore(t)
	plan, err := PlanEnrollment(st, validEnrollmentRequest())
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

	got, err := st.GetSpoke("new-spoke")
	if err != nil {
		t.Fatalf("GetSpoke after PlanEnrollment: %v", err)
	}
	if len(got.Tokens) != 1 || got.Tokens[0] != plan.BearerToken {
		t.Errorf("got tokens %v, want exactly the returned bearer token", got.Tokens)
	}
	if len(got.Certs) != 1 || got.Certs[0].Name != "new-cert" {
		t.Errorf("got certs %+v, want one new-cert", got.Certs)
	}
}

// TestPlanEnrollment_ExistingSpokeErrors is the scope boundary that
// distinguishes PlanEnrollment from Plan: enrolling an already-configured
// spoke isn't this function's job at all, not even to reuse its existing
// token the way Plan does for an additional certificate.
func TestPlanEnrollment_ExistingSpokeErrors(t *testing.T) {
	st := testStore(t)
	req := validEnrollmentRequest()
	req.SpokeID = "existing-spoke"

	_, err := PlanEnrollment(st, req)
	if err == nil {
		t.Fatal("expected an error enrolling a spoke that already exists, got nil")
	}
}

func TestPlanEnrollment_UnknownDNSProviderErrors(t *testing.T) {
	st := testStore(t)
	req := validEnrollmentRequest()
	req.DNSProvider = "does-not-exist"

	_, err := PlanEnrollment(st, req)
	if err == nil {
		t.Fatal("expected an error for a dns_provider that doesn't exist on the hub, got nil")
	}
}

func TestPlanEnrollment_MissingRequiredFieldsError(t *testing.T) {
	st := testStore(t)
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
		if _, err := PlanEnrollment(st, req); err == nil {
			t.Errorf("missing %s: expected an error, got nil", c.name)
		}
	}
}

func TestPlanEnrollment_DomainDNSProvidersRejectsDomainNotInRequest(t *testing.T) {
	st := testStore(t)
	req := validEnrollmentRequest()
	req.DomainDNSProviders = map[string]string{"other.example.org": "route53_main"}

	_, err := PlanEnrollment(st, req)
	if err == nil {
		t.Fatal("expected an error for domain_dns_providers referencing a domain not in Domains, got nil")
	}
}

// TestPlanEnrollment_SuccessiveCallsGenerateDistinctTokens guards against
// a copy-paste mistake reusing the same GenerateToken result for both the
// bearer token and the enrollment secret, or generating either
// non-randomly.
func TestPlanEnrollment_SuccessiveCallsGenerateDistinctTokens(t *testing.T) {
	st := testStore(t)
	first, err := PlanEnrollment(st, validEnrollmentRequest())
	if err != nil {
		t.Fatalf("first PlanEnrollment: %v", err)
	}
	second := validEnrollmentRequest()
	second.SpokeID = "new-spoke-2"
	secondPlan, err := PlanEnrollment(st, second)
	if err != nil {
		t.Fatalf("second PlanEnrollment: %v", err)
	}
	if first.BearerToken == secondPlan.BearerToken {
		t.Error("two successive calls generated the identical bearer token")
	}
	if first.EnrollmentSecret == secondPlan.EnrollmentSecret {
		t.Error("two successive calls generated the identical enrollment secret")
	}
}

func TestPlanRotation_UnknownSpokeErrors(t *testing.T) {
	st := testStore(t)
	_, err := PlanRotation(st, RotationRequest{SpokeID: "no-such-spoke"})
	if err == nil {
		t.Fatal("expected an error for a spoke that doesn't exist, got nil")
	}
}

func TestPlanRotation_MissingSpokeIDErrors(t *testing.T) {
	st := testStore(t)
	_, err := PlanRotation(st, RotationRequest{})
	if err == nil {
		t.Fatal("expected an error for an empty spoke id, got nil")
	}
}

// TestPlanRotation_AddsTokenWithoutTouchingExisting proves PlanRotation's
// actual guarantee: a real, freshly generated token is added alongside
// the spoke's existing one - not a copy of anything already on the spoke,
// and not a replacement for it either.
func TestPlanRotation_AddsTokenWithoutTouchingExisting(t *testing.T) {
	st := testStore(t)
	result, err := PlanRotation(st, RotationRequest{SpokeID: "existing-spoke"})
	if err != nil {
		t.Fatalf("PlanRotation: %v", err)
	}

	if len(result.NewToken) != 64 { // 32 bytes hex-encoded, same as GenerateToken
		t.Errorf("got new token length %d, want 64", len(result.NewToken))
	}
	if result.NewToken == "existing-token-value" {
		t.Error("got the spoke's existing token back, want a freshly generated one")
	}

	got, err := st.GetSpoke("existing-spoke")
	if err != nil {
		t.Fatalf("GetSpoke after PlanRotation: %v", err)
	}
	if len(got.Tokens) != 2 {
		t.Fatalf("got %d tokens, want 2 (existing plus rotated)", len(got.Tokens))
	}
	byToken := map[string]bool{got.Tokens[0]: true, got.Tokens[1]: true}
	if !byToken["existing-token-value"] {
		t.Error("existing-token-value is gone - PlanRotation must not remove the old token, only add a new one")
	}
	if !byToken[result.NewToken] {
		t.Error("the new token was not actually persisted")
	}
}

// TestPlanRotation_SuccessiveCallsGenerateDistinctTokens proves calling
// PlanRotation twice in a row (e.g. an operator retrying) doesn't hand
// back the same token each time.
func TestPlanRotation_SuccessiveCallsGenerateDistinctTokens(t *testing.T) {
	st := testStore(t)
	first, err := PlanRotation(st, RotationRequest{SpokeID: "existing-spoke"})
	if err != nil {
		t.Fatalf("first PlanRotation: %v", err)
	}
	second, err := PlanRotation(st, RotationRequest{SpokeID: "existing-spoke"})
	if err != nil {
		t.Fatalf("second PlanRotation: %v", err)
	}
	if first.NewToken == second.NewToken {
		t.Error("two successive calls generated the identical token")
	}
}
