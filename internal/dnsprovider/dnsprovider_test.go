package dnsprovider

import (
	"testing"

	"github.com/tmhal5l13/acme-agent/config"
)

func TestNew_KnownTypesBuildWithoutError(t *testing.T) {
	// These only construct the provider object (client setup); they don't
	// require real credentials to be present. pdns's constructor does
	// attempt one best-effort API-version probe (failure is only logged,
	// not returned), so api_url points at a port nothing listens on to
	// fail that probe fast (connection refused) instead of timing out.
	cases := []config.DNSProviderConfig{
		{Type: "cloudflare", APIToken: "dummy"},
		{Type: "route53"},
		{Type: "route53", AccessKeyID: "dummy", SecretAccessKey: "dummy"},
		{Type: "route53", AccessKeyID: "dummy", SecretAccessKey: "dummy", SessionToken: "dummy"},
		{Type: "godaddy", APIKey: "dummy", APISecret: "dummy"},
		{Type: "pdns", APIKey: "dummy", APIURL: "http://127.0.0.1:1"},
		{Type: "rfc2136", Nameserver: "127.0.0.1:53", TSIGKey: "dummy", TSIGSecret: "ZHVtbXk=", TSIGAlgorithm: "hmac-sha256."},
	}
	for _, cfg := range cases {
		if _, err := New(cfg); err != nil {
			t.Errorf("New(%+v) returned unexpected error: %v", cfg, err)
		}
	}
}

func TestNew_UnknownTypeErrors(t *testing.T) {
	_, err := New(config.DNSProviderConfig{Type: "not-a-real-provider"})
	if err == nil {
		t.Fatal("expected an error for an unknown provider type, got nil")
	}
}

// TestNew_Route53RejectsIncompleteCredentials proves lego's own
// validation (AccessKeyID and SecretAccessKey must be supplied together;
// SessionToken alone isn't meaningful) surfaces through New as a real
// error, not silently accepted or dropped - acme-agent doesn't duplicate
// this check itself, so this is what proves lego's still doing it.
func TestNew_Route53RejectsIncompleteCredentials(t *testing.T) {
	cases := []config.DNSProviderConfig{
		{Type: "route53", AccessKeyID: "dummy"},     // SecretAccessKey missing
		{Type: "route53", SecretAccessKey: "dummy"}, // AccessKeyID missing
		{Type: "route53", SessionToken: "dummy"},    // SessionToken alone, no AccessKeyID/SecretAccessKey
	}
	for _, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v): expected an error for incomplete route53 credentials, got nil", cfg)
		}
	}
}
