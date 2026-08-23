package hubstore

import "github.com/tmhal5l13/acme-agent/config"

// providerCfgFixture is a minimal valid DNS provider config for tests that
// need a real dns_providers row to exist (e.g. to satisfy
// UpsertSpokeCert's dns_provider-exists check) but don't care about its
// contents.
func providerCfgFixture() config.DNSProviderConfig {
	return config.DNSProviderConfig{Type: "cloudflare", APIToken: "dummy"}
}

// certFixture is a minimal valid cert assignment referencing dnsProvider,
// for tests that need a real spoke_certs row but don't care about its
// domains.
func certFixture(name, dnsProvider string) config.SpokeCertConfig {
	return config.SpokeCertConfig{Name: name, Domains: []string{"example.com"}, DNSProvider: dnsProvider}
}
