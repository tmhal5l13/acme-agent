package hubstore

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/tmhal5l13/acme-agent/config"
)

// UpsertSpokeCert creates or updates one certificate a spoke is
// authorized to manage. Runs config.ValidateCertName/ValidateDomain
// itself (not just left to callers) - see ARCHITECTURE.md and this
// package's callers for why: once desired-state writes go straight here
// instead of through a YAML load, this is the one place guaranteed to run
// on every write path (the web admin UI, cmd/acme-onboard,
// acme-hub --generate-token, --import-config), so it can't be skipped by
// a caller forgetting to call it separately - and ValidateCertName in
// particular is a real path-traversal guard, not just a formatting nicety.
//
// Also checks, transactionally: spoke exists; dns_provider exists;
// every DomainDNSProviders value exists; every DomainDNSProviders key is
// in Domains - the exact checks config.HubConfig.validate() used to make
// via a plain map lookup against the whole YAML document at once. Only
// the store layer can make these atomic against a concurrent write (e.g.
// a DNS provider being deleted between a caller's own pre-check and this
// call) now that there's no single-document validation pass.
func (s *Store) UpsertSpokeCert(spokeID string, cert config.SpokeCertConfig) error {
	if err := config.ValidateCertName(cert.Name); err != nil {
		return fmt.Errorf("upsert cert for spoke %q: %w", spokeID, err)
	}
	if len(cert.Domains) == 0 {
		return fmt.Errorf("upsert cert %q for spoke %q: at least one domain is required", cert.Name, spokeID)
	}
	for _, d := range cert.Domains {
		if err := config.ValidateDomain(d); err != nil {
			return fmt.Errorf("upsert cert %q for spoke %q: %w", cert.Name, spokeID, err)
		}
	}
	if cert.DNSProvider == "" {
		return fmt.Errorf("upsert cert %q for spoke %q: dns provider is required", cert.Name, spokeID)
	}
	domainSet := make(map[string]bool, len(cert.Domains))
	for _, d := range cert.Domains {
		domainSet[d] = true
	}
	for domain := range cert.DomainDNSProviders {
		if !domainSet[domain] {
			return fmt.Errorf("upsert cert %q for spoke %q: domain_dns_providers references domain %q, which is not in domains",
				cert.Name, spokeID, domain)
		}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("upsert cert %q for spoke %q: begin transaction: %w", cert.Name, spokeID, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	var spokeExists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM spokes WHERE id = ?)`, spokeID).Scan(&spokeExists); err != nil {
		return fmt.Errorf("upsert cert %q for spoke %q: check spoke exists: %w", cert.Name, spokeID, err)
	}
	if !spokeExists {
		return fmt.Errorf("upsert cert %q for spoke %q: %w", cert.Name, spokeID, ErrNotFound)
	}

	providers := append([]string{cert.DNSProvider}, mapValues(cert.DomainDNSProviders)...)
	for _, provider := range providers {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM dns_providers WHERE name = ?)`, provider).Scan(&exists); err != nil {
			return fmt.Errorf("upsert cert %q for spoke %q: check dns_provider %q exists: %w", cert.Name, spokeID, provider, err)
		}
		if !exists {
			return fmt.Errorf("upsert cert %q for spoke %q: dns_provider %q is not defined", cert.Name, spokeID, provider)
		}
	}

	domainsJSON, err := json.Marshal(cert.Domains)
	if err != nil {
		return fmt.Errorf("upsert cert %q for spoke %q: encode domains: %w", cert.Name, spokeID, err)
	}
	overridesJSON, err := marshalOrEmptyObject(cert.DomainDNSProviders)
	if err != nil {
		return fmt.Errorf("upsert cert %q for spoke %q: encode domain_dns_providers: %w", cert.Name, spokeID, err)
	}

	if _, err := tx.Exec(`
		INSERT INTO spoke_certs (spoke_id, name, domains_json, dns_provider, domain_dns_providers_json, renew_before_ns)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (spoke_id, name) DO UPDATE SET
			domains_json              = excluded.domains_json,
			dns_provider              = excluded.dns_provider,
			domain_dns_providers_json = excluded.domain_dns_providers_json,
			renew_before_ns           = excluded.renew_before_ns`,
		spokeID, cert.Name, domainsJSON, cert.DNSProvider, overridesJSON, int64(cert.RenewBefore)); err != nil {
		return fmt.Errorf("upsert cert %q for spoke %q: %w", cert.Name, spokeID, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("upsert cert %q for spoke %q: commit: %w", cert.Name, spokeID, err)
	}
	return nil
}

// RemoveSpokeCert removes one certificate assignment from a spoke.
// Returns ErrNotFound if spokeID has no certificate named certName.
func (s *Store) RemoveSpokeCert(spokeID, certName string) error {
	result, err := s.db.Exec(`DELETE FROM spoke_certs WHERE spoke_id = ? AND name = ?`, spokeID, certName)
	if err != nil {
		return fmt.Errorf("remove cert %q for spoke %q: %w", certName, spokeID, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("remove cert %q for spoke %q: rows affected: %w", certName, spokeID, err)
	}
	if affected == 0 {
		return fmt.Errorf("remove cert %q for spoke %q: %w", certName, spokeID, ErrNotFound)
	}
	return nil
}

// allSpokeCerts returns every spoke's certificates, keyed by spoke ID -
// the shared query AllSpokes (spokes.go) and RemoveDNSProvider's in-use
// check (dnsproviders.go) both need.
func (s *Store) allSpokeCerts() (map[string][]config.SpokeCertConfig, error) {
	return scanSpokeCerts(s.db.Query(`SELECT spoke_id, name, domains_json, dns_provider, domain_dns_providers_json, renew_before_ns FROM spoke_certs`))
}

// spokeCerts returns one spoke's certificates - GetSpoke's (spokes.go)
// single-spoke counterpart to allSpokeCerts.
func (s *Store) spokeCerts(spokeID string) ([]config.SpokeCertConfig, error) {
	byspoke, err := scanSpokeCerts(s.db.Query(
		`SELECT spoke_id, name, domains_json, dns_provider, domain_dns_providers_json, renew_before_ns FROM spoke_certs WHERE spoke_id = ?`, spokeID))
	if err != nil {
		return nil, err
	}
	return byspoke[spokeID], nil
}

func scanSpokeCerts(rows *sql.Rows, queryErr error) (map[string][]config.SpokeCertConfig, error) {
	if queryErr != nil {
		return nil, fmt.Errorf("query spoke certs: %w", queryErr)
	}
	defer rows.Close()

	byspoke := make(map[string][]config.SpokeCertConfig)
	for rows.Next() {
		var spokeID string
		var cert config.SpokeCertConfig
		var domainsJSON, overridesJSON string
		var renewBeforeNS int64
		if err := rows.Scan(&spokeID, &cert.Name, &domainsJSON, &cert.DNSProvider, &overridesJSON, &renewBeforeNS); err != nil {
			return nil, fmt.Errorf("scan spoke cert row: %w", err)
		}
		if err := json.Unmarshal([]byte(domainsJSON), &cert.Domains); err != nil {
			return nil, fmt.Errorf("decode domains for spoke %q cert %q: %w", spokeID, cert.Name, err)
		}
		if err := json.Unmarshal([]byte(overridesJSON), &cert.DomainDNSProviders); err != nil {
			return nil, fmt.Errorf("decode domain_dns_providers for spoke %q cert %q: %w", spokeID, cert.Name, err)
		}
		cert.RenewBefore = config.Duration(renewBeforeNS)
		byspoke[spokeID] = append(byspoke[spokeID], cert)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate spoke cert rows: %w", err)
	}
	return byspoke, nil
}

// mapValues returns m's values as a slice, in unspecified order - used
// where the caller only needs to check membership/existence of each
// value, not display them in a stable order.
func mapValues(m map[string]string) []string {
	values := make([]string, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}
	return values
}

// marshalOrEmptyObject JSON-encodes m, treating a nil map as "{}" rather
// than encoding/json's own "null" - domain_dns_providers_json has a
// NOT NULL constraint and allSpokeCerts unmarshals it straight back into
// a map field, which a literal "null" would leave nil (fine) but a
// missing/absent value would fail to scan into a NOT NULL TEXT column at
// all.
func marshalOrEmptyObject(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}
