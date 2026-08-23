package config

import (
	"fmt"
	"path/filepath"
)

// LegacyDesiredState is the shape spokes:/dns_providers: used to have
// directly under the hub's config.yaml, before that desired state moved
// into the database (see internal/hubstore). Exists only for
// acme-hub --import-config, a one-shot migration path for a config file
// written before that cutover - HubConfig itself no longer has these
// fields at all (see HubConfig.LegacySpokes/.LegacyDNSProviders, which
// only detect that a config file still has these keys, so LoadHubConfig
// can point the operator here instead of silently ignoring them).
type LegacyDesiredState struct {
	DNSProviders map[string]DNSProviderConfig `yaml:"dns_providers"`
	Spokes       map[string]SpokeEntry        `yaml:"spokes"`
}

// LoadLegacyDesiredState reads, expands, and validates just the
// spokes:/dns_providers: sections of a pre-cutover hub config file at
// path - the rest of that file (listen_addr, data_dir, etc.) is ignored
// entirely, since --import-config's caller already has its own, current
// config.yaml for those. ${VAR} references still expand the same way
// LoadHubConfig's always have, from an acme-hub.env file next to path,
// so a legacy file's real secret values (spoke tokens, DNS provider
// credentials) are recovered correctly during import, not left as
// literal "${VAR}" strings.
func LoadLegacyDesiredState(path string) (*LegacyDesiredState, error) {
	env, err := fileEnvSource(filepath.Join(filepath.Dir(path), hubEnvFileName))
	if err != nil {
		return nil, err
	}

	state, err := loadYAML[LegacyDesiredState](path, env)
	if err != nil {
		return nil, err
	}

	if err := state.validate(); err != nil {
		return nil, fmt.Errorf("invalid legacy desired state: %w", err)
	}

	return state, nil
}

// validate is HubConfig.validate()'s former spoke/DNS-provider validation
// loop, scoped to just these two fields - the same checks a config file
// like this one used to get for free at YAML-load time, before that
// logic moved to internal/hubstore.UpsertSpokeCert for the live,
// database-backed path. Kept here too so a bad legacy file is rejected
// up front, before --import-config has written anything through that
// live path at all, rather than failing partway through.
func (s *LegacyDesiredState) validate() error {
	seenTokens := make(map[string]string, len(s.Spokes))
	for spokeID, spoke := range s.Spokes {
		if len(spoke.Tokens) == 0 {
			return fmt.Errorf("spokes[%s]: at least one entry under tokens is required", spokeID)
		}
		for _, token := range spoke.Tokens {
			if token == "" {
				return fmt.Errorf("spokes[%s]: tokens entries must not be empty", spokeID)
			}
			if other, ok := seenTokens[token]; ok {
				return fmt.Errorf("spokes[%s]: token is also used by spokes[%s] — tokens must be unique, they're how a request is identified", spokeID, other)
			}
			seenTokens[token] = spokeID
		}

		if len(spoke.Certs) == 0 {
			return fmt.Errorf("spokes[%s]: at least one entry under certs is required", spokeID)
		}

		seenNames := make(map[string]bool, len(spoke.Certs))
		for _, cert := range spoke.Certs {
			if err := ValidateCertName(cert.Name); err != nil {
				return fmt.Errorf("spokes[%s]: %w", spokeID, err)
			}
			if seenNames[cert.Name] {
				return fmt.Errorf("spokes[%s]: duplicate cert name %q", spokeID, cert.Name)
			}
			seenNames[cert.Name] = true

			if len(cert.Domains) == 0 {
				return fmt.Errorf("spokes[%s].certs[%s]: at least one domain is required", spokeID, cert.Name)
			}
			for _, d := range cert.Domains {
				if err := ValidateDomain(d); err != nil {
					return fmt.Errorf("spokes[%s].certs[%s]: %w", spokeID, cert.Name, err)
				}
			}
			if _, ok := s.DNSProviders[cert.DNSProvider]; !ok {
				return fmt.Errorf("spokes[%s].certs[%s]: dns_provider %q is not defined under dns_providers", spokeID, cert.Name, cert.DNSProvider)
			}

			domainSet := make(map[string]bool, len(cert.Domains))
			for _, d := range cert.Domains {
				domainSet[d] = true
			}
			for domain, provider := range cert.DomainDNSProviders {
				if !domainSet[domain] {
					return fmt.Errorf("spokes[%s].certs[%s]: domain_dns_providers references domain %q, which is not in this cert's domains", spokeID, cert.Name, domain)
				}
				if _, ok := s.DNSProviders[provider]; !ok {
					return fmt.Errorf("spokes[%s].certs[%s]: domain_dns_providers[%s]: dns_provider %q is not defined under dns_providers", spokeID, cert.Name, domain, provider)
				}
			}
		}
	}

	return nil
}
