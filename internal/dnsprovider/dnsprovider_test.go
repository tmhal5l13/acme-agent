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
