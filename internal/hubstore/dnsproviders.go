package hubstore

import (
	"encoding/json"
	"fmt"

	"github.com/tmhal5l13/acme-agent/config"
)

// UpsertDNSProvider creates or updates one named DNS provider config,
// credentials included. Doesn't validate cfg.Type against the set of
// provider types internal/dnsprovider actually implements (hubstore
// doesn't import that package, and never has) - an unknown/unsupported
// type surfaces later, when
// internal/hubapi.buildState tries to actually construct a
// challenge.Provider from it.
func (s *Store) UpsertDNSProvider(name string, cfg config.DNSProviderConfig) error {
	if name == "" {
		return fmt.Errorf("upsert dns provider: name is required")
	}

	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("upsert dns provider %q: encode config: %w", name, err)
	}

	if _, err := s.db.Exec(`
		INSERT INTO dns_providers (name, config_json) VALUES (?, ?)
		ON CONFLICT (name) DO UPDATE SET config_json = excluded.config_json`,
		name, configJSON); err != nil {
		return fmt.Errorf("upsert dns provider %q: %w", name, err)
	}
	return nil
}

// RemoveDNSProvider removes a named DNS provider. Refuses (ErrInUse) if
// any spoke's certificate still references it - as its default
// dns_provider or as a domain_dns_providers override value - the reverse
// check config.HubConfig.validate() never needed before, since deleting a
// dns_providers entry out from under a referencing cert used to only ever
// be a YAML edit an operator could get validate()-rejected on next load,
// not a live runtime operation. Returns ErrNotFound if name doesn't exist.
func (s *Store) RemoveDNSProvider(name string) error {
	certsBySpoke, err := s.allSpokeCerts()
	if err != nil {
		return fmt.Errorf("remove dns provider %q: %w", name, err)
	}
	for spokeID, certs := range certsBySpoke {
		for _, cert := range certs {
			if cert.DNSProvider == name {
				return fmt.Errorf("remove dns provider %q: %w (spoke %q cert %q uses it as the default provider)", name, ErrInUse, spokeID, cert.Name)
			}
			for _, override := range cert.DomainDNSProviders {
				if override == name {
					return fmt.Errorf("remove dns provider %q: %w (spoke %q cert %q overrides a domain to it)", name, ErrInUse, spokeID, cert.Name)
				}
			}
		}
	}

	result, err := s.db.Exec(`DELETE FROM dns_providers WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("remove dns provider %q: %w", name, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("remove dns provider %q: rows affected: %w", name, err)
	}
	if affected == 0 {
		return fmt.Errorf("remove dns provider %q: %w", name, ErrNotFound)
	}
	return nil
}

// DNSProviderExists reports whether a DNS provider named name has been
// created.
func (s *Store) DNSProviderExists(name string) (bool, error) {
	var exists bool
	if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM dns_providers WHERE name = ?)`, name).Scan(&exists); err != nil {
		return false, fmt.Errorf("check dns provider %q exists: %w", name, err)
	}
	return exists, nil
}

// AllDNSProviders returns every configured DNS provider, keyed by name.
func (s *Store) AllDNSProviders() (map[string]config.DNSProviderConfig, error) {
	rows, err := s.db.Query(`SELECT name, config_json FROM dns_providers`)
	if err != nil {
		return nil, fmt.Errorf("query all dns providers: %w", err)
	}
	defer rows.Close()

	providers := make(map[string]config.DNSProviderConfig)
	for rows.Next() {
		var name, configJSON string
		if err := rows.Scan(&name, &configJSON); err != nil {
			return nil, fmt.Errorf("scan dns provider row: %w", err)
		}
		var cfg config.DNSProviderConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return nil, fmt.Errorf("decode dns provider %q: %w", name, err)
		}
		providers[name] = cfg
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate dns provider rows: %w", err)
	}
	return providers, nil
}
