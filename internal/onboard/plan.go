// Package onboard generates the bearer token and spoke config.yaml needed
// to add one certificate to one spoke, writing the hub side straight into
// the database (internal/hubstore) so the two sides can never drift out
// of sync the way hand-editing two separate files used to risk (a typo'd
// cert name between them used to silently produce a 403 the first time
// the spoke tried to use it).
package onboard

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
)

// Request describes the certificate being onboarded.
type Request struct {
	SpokeID     string
	CertName    string
	Domains     []string
	DNSProvider string // default dns_provider for every domain above; must already exist in the hub's dns_providers

	// DomainDNSProviders optionally overrides DNSProvider for specific
	// domains — keys must be entries already in Domains, values must
	// already exist in the hub's dns_providers, same as DNSProvider.
	// Optional and almost always empty; see
	// config.SpokeCertConfig.DomainDNSProviders for why a cert's domains
	// can span more than one DNS provider at all.
	DomainDNSProviders map[string]string

	HubURL string
	// HubTLSCertFile is the local path, on this new spoke, where the hub's
	// certificate will be copied to — Plan only writes this path into the
	// generated config, it can't copy the file itself, since it has no
	// access to the hub's filesystem. See internal/hubclient for why the
	// spoke pins this exact certificate rather than trusting a CA.
	HubTLSCertFile string
	ReloadHook     string
	ACMEEmail      string
	ACMEEnv        string // "staging" or "production"
}

// Result is everything Plan produced: the spoke's bearer token (freshly
// generated for a new spoke, reused for an existing one) and its complete
// config.yaml — the hub side has already been written directly into
// store by the time Plan returns, so there's nothing left to paste.
type Result struct {
	Token           string
	IsNewSpoke      bool
	SpokeConfigYAML string
}

// validateCertRequest checks the fields common to onboarding a
// certificate onto a spoke regardless of which flow is doing it (Plan's
// full-request workflow, or PlanEnrollment's new-spoke-only one): a spoke
// id, cert name, at least one domain, and that dnsProvider (and any
// domainDNSProviders override) actually exists in the hub's database.
func validateCertRequest(store *hubstore.Store, spokeID, certName string, domains []string, dnsProvider string, domainDNSProviders map[string]string) error {
	if spokeID == "" {
		return fmt.Errorf("spoke id is required")
	}
	if certName == "" {
		return fmt.Errorf("cert name is required")
	}
	if len(domains) == 0 {
		return fmt.Errorf("at least one domain is required")
	}
	if dnsProvider == "" {
		return fmt.Errorf("dns provider is required")
	}
	if exists, err := store.DNSProviderExists(dnsProvider); err != nil {
		return fmt.Errorf("check dns_provider %q: %w", dnsProvider, err)
	} else if !exists {
		return fmt.Errorf("dns_provider %q is not defined on the hub — add it first", dnsProvider)
	}

	domainSet := make(map[string]bool, len(domains))
	for _, d := range domains {
		domainSet[d] = true
	}
	for domain, provider := range domainDNSProviders {
		if !domainSet[domain] {
			return fmt.Errorf("domain_dns_providers references domain %q, which is not in Domains", domain)
		}
		if exists, err := store.DNSProviderExists(provider); err != nil {
			return fmt.Errorf("check dns_provider %q: %w", provider, err)
		} else if !exists {
			return fmt.Errorf("domain_dns_providers[%s]: dns_provider %q is not defined on the hub — add it first", domain, provider)
		}
	}
	return nil
}

// Plan validates req and writes it directly into store: a new spoke gets
// a fresh cryptographically random token and its one certificate; adding
// a certificate to a spoke that already exists reuses its existing token
// (the first one on record) rather than generating — and thereby
// invalidating — a new one.
func Plan(store *hubstore.Store, req Request) (*Result, error) {
	if err := validateCertRequest(store, req.SpokeID, req.CertName, req.Domains, req.DNSProvider, req.DomainDNSProviders); err != nil {
		return nil, err
	}
	if req.HubURL == "" {
		return nil, fmt.Errorf("hub url is required")
	}
	if req.HubTLSCertFile == "" {
		return nil, fmt.Errorf("hub tls cert file is required")
	}
	if req.ACMEEnv != "staging" && req.ACMEEnv != "production" {
		return nil, fmt.Errorf("acme environment must be %q or %q, got %q", "staging", "production", req.ACMEEnv)
	}

	existing, err := store.GetSpoke(req.SpokeID)
	spokeExists := true
	switch {
	case errors.Is(err, hubstore.ErrNotFound):
		spokeExists = false
	case err != nil:
		return nil, fmt.Errorf("look up spoke %q: %w", req.SpokeID, err)
	}

	var token string
	if spokeExists {
		for _, c := range existing.Certs {
			if c.Name == req.CertName {
				return nil, fmt.Errorf("spoke %q already has a certificate named %q", req.SpokeID, req.CertName)
			}
		}
		if len(existing.Tokens) == 0 {
			return nil, fmt.Errorf("spoke %q has no tokens on the hub — this shouldn't be possible for an already-created spoke", req.SpokeID)
		}
		token = existing.Tokens[0] // the primary/first token; see PlanRotation for adding a second during rotation
	} else {
		t, err := GenerateToken()
		if err != nil {
			return nil, err
		}
		token = t
		if err := store.CreateSpoke(req.SpokeID, token); err != nil {
			return nil, fmt.Errorf("create spoke %q: %w", req.SpokeID, err)
		}
	}

	newCert := config.SpokeCertConfig{
		Name:               req.CertName,
		Domains:            req.Domains,
		DNSProvider:        req.DNSProvider,
		DomainDNSProviders: req.DomainDNSProviders,
	}
	if err := store.UpsertSpokeCert(req.SpokeID, newCert); err != nil {
		return nil, fmt.Errorf("add cert %q to spoke %q: %w", req.CertName, req.SpokeID, err)
	}

	// existing.Certs carries no reload_hook — that field is spoke-local
	// only (see SpokeLocalCertConfig) and never appears in the hub's own
	// desired state, so Plan has no way to know what an existing cert's
	// hook already is; those entries get the same commented-out
	// placeholder a fresh cert with no ReloadHook gets, and the operator
	// re-adds the real command by hand.
	certs := make([]SpokeCert, 0, len(existing.Certs)+1)
	for _, c := range existing.Certs {
		certs = append(certs, SpokeCert{Name: c.Name, Domains: c.Domains})
	}
	certs = append(certs, SpokeCert{Name: req.CertName, Domains: req.Domains, ReloadHook: req.ReloadHook})

	return &Result{
		Token:      token,
		IsNewSpoke: !spokeExists,
		SpokeConfigYAML: BuildSpokeConfigYAML(SpokeConfigParams{
			HubURL:         req.HubURL,
			HubTLSCertFile: req.HubTLSCertFile,
			ACMEEnv:        req.ACMEEnv,
			ACMEEmail:      req.ACMEEmail,
		}, certs),
	}, nil
}

// SpokeCert is one certificate a generated spoke config.yaml lists under
// certs: - the shape both Plan (adding one certificate to a spoke,
// alongside whatever it already has) and acme-spoke --load-token
// (writing a freshly-enrolled spoke's complete cert list in one shot)
// need to describe.
type SpokeCert struct {
	Name       string
	Domains    []string
	ReloadHook string // empty prints a commented-out placeholder instead
}

// SpokeConfigParams is everything BuildSpokeConfigYAML needs beyond the
// cert list itself.
type SpokeConfigParams struct {
	HubURL         string
	HubTLSCertFile string
	ACMEEnv        string
	ACMEEmail      string
}

// BuildSpokeConfigYAML emits a complete spoke config.yaml listing every
// cert in certs - not just one being added, so regenerating the config
// for an existing spoke's second or third certificate (see Plan) doesn't
// silently produce a config.yaml that only lists the newest one, dropping
// the others from local management entirely.
func BuildSpokeConfigYAML(params SpokeConfigParams, certs []SpokeCert) string {
	var b strings.Builder
	fmt.Fprintf(&b, "hub_url: %q\n", params.HubURL)
	fmt.Fprintf(&b, "hub_token: \"${HUB_TOKEN}\"\n")
	fmt.Fprintf(&b, "hub_tls_cert_file: %q # copy from the hub's data_dir/tls/cert.pem — verify its printed sha256 fingerprint matches\n\n", params.HubTLSCertFile)
	fmt.Fprintf(&b, "acme:\n")
	fmt.Fprintf(&b, "  environment: %s\n", params.ACMEEnv)
	fmt.Fprintf(&b, "  email: %s\n\n", params.ACMEEmail)
	fmt.Fprintf(&b, "data_dir: /var/lib/acme-spoke\n\n")
	fmt.Fprintf(&b, "certs:\n")
	for _, c := range certs {
		fmt.Fprintf(&b, "  - name: %s\n", c.Name)
		fmt.Fprintf(&b, "    domains: [%s]\n", strings.Join(c.Domains, ", "))
		if c.ReloadHook != "" {
			fmt.Fprintf(&b, "    reload_hook: %q\n", c.ReloadHook)
		} else {
			fmt.Fprintf(&b, "    # reload_hook: \"systemctl reload nginx\"\n")
		}
	}
	return b.String()
}

// EnrollmentRequest describes the certificate being enrolled for a
// brand-new spoke via acme-hub --generate-token. Unlike Request, it never
// describes an already-existing spoke (see PlanEnrollment) and carries
// none of the spoke-local generation concerns (ACME email/environment,
// reload hook) - those are supplied directly to acme-spoke --load-token
// at enrollment time instead, since PlanEnrollment never generates a
// spoke config.yaml itself; that only happens once the spoke actually
// redeems its token against POST /v1/enroll.
type EnrollmentRequest struct {
	SpokeID            string
	CertName           string
	Domains            []string
	DNSProvider        string
	DomainDNSProviders map[string]string
	// HubURL is where the new spoke will dial to reach the hub - embedded
	// directly in the printed enrollment token (see internal/enrolltoken),
	// not just written into the spoke config.yaml it eventually generates,
	// so acme-spoke --load-token needs nothing beyond that one token
	// string.
	HubURL string
}

// EnrollmentPlan is what PlanEnrollment generates for the caller to hand
// off to the new spoke - the hub side (spoke, its token, its one
// certificate) has already been written directly into store by the time
// PlanEnrollment returns.
type EnrollmentPlan struct {
	// BearerToken is the new spoke's real, permanent bearer token -
	// stored (via hubstore.Store.InsertEnrollmentToken, by the caller,
	// not by PlanEnrollment itself) alongside EnrollmentSecret, and handed
	// back to the spoke only once it successfully redeems that secret.
	BearerToken string
	// EnrollmentSecret is the one-time secret to insert into hubstore
	// (see internal/hubstore.Store.InsertEnrollmentToken) and embed in
	// the token handed to the new spoke - see internal/enrolltoken.
	EnrollmentSecret string
}

// PlanEnrollment validates req and writes the new spoke, its token, and
// its one certificate directly into store - see ARCHITECTURE.md "Spoke
// enrollment" for the full workflow this is one step of. Unlike Plan,
// which reuses an existing spoke's token when adding another
// certificate, PlanEnrollment requires req.SpokeID to not already exist:
// enrolling an already-known spoke isn't this function's job - add a
// certificate to it with Plan, or rotate its token with PlanRotation.
func PlanEnrollment(store *hubstore.Store, req EnrollmentRequest) (*EnrollmentPlan, error) {
	if err := validateCertRequest(store, req.SpokeID, req.CertName, req.Domains, req.DNSProvider, req.DomainDNSProviders); err != nil {
		return nil, err
	}
	if req.HubURL == "" {
		return nil, fmt.Errorf("hub url is required")
	}
	if exists, err := store.SpokeExists(req.SpokeID); err != nil {
		return nil, fmt.Errorf("check spoke %q exists: %w", req.SpokeID, err)
	} else if exists {
		return nil, fmt.Errorf("spoke %q already exists — PlanEnrollment is for brand-new spokes only; use Plan to add a certificate to an existing spoke, or PlanRotation to rotate its token", req.SpokeID)
	}

	bearerToken, err := GenerateToken()
	if err != nil {
		return nil, err
	}
	secret, err := GenerateToken()
	if err != nil {
		return nil, err
	}

	if err := store.CreateSpoke(req.SpokeID, bearerToken); err != nil {
		return nil, fmt.Errorf("create spoke %q: %w", req.SpokeID, err)
	}
	newCert := config.SpokeCertConfig{
		Name:               req.CertName,
		Domains:            req.Domains,
		DNSProvider:        req.DNSProvider,
		DomainDNSProviders: req.DomainDNSProviders,
	}
	if err := store.UpsertSpokeCert(req.SpokeID, newCert); err != nil {
		return nil, fmt.Errorf("add cert %q to spoke %q: %w", req.CertName, req.SpokeID, err)
	}

	return &EnrollmentPlan{
		BearerToken:      bearerToken,
		EnrollmentSecret: secret,
	}, nil
}

// RotationRequest identifies the spoke whose bearer token is being
// rotated.
type RotationRequest struct {
	SpokeID string
}

// RotationResult is what PlanRotation generates: a freshly minted token,
// already written into store *alongside* the spoke's existing one(s) -
// see PlanRotation's doc comment for the full workflow this is one step
// of.
type RotationResult struct {
	NewToken string
}

// PlanRotation generates a new token for an already-configured spoke and
// writes it into store alongside its existing token(s) - both are valid
// simultaneously until the old one is explicitly removed (step 3 below).
//
// The full rotation workflow this is one step of: (1) call PlanRotation -
// both the old and new token are now valid; (2) update the spoke's own
// hub_token to the new value, restart the spoke, confirm it's working;
// (3) remove the old token (hubstore.Store.RemoveSpokeToken, or the web
// admin UI) to complete the rotation.
func PlanRotation(store *hubstore.Store, req RotationRequest) (*RotationResult, error) {
	if req.SpokeID == "" {
		return nil, fmt.Errorf("spoke id is required")
	}
	if exists, err := store.SpokeExists(req.SpokeID); err != nil {
		return nil, fmt.Errorf("check spoke %q exists: %w", req.SpokeID, err)
	} else if !exists {
		return nil, fmt.Errorf("spoke %q does not exist", req.SpokeID)
	}

	newToken, err := GenerateToken()
	if err != nil {
		return nil, err
	}
	if err := store.AddSpokeToken(req.SpokeID, newToken); err != nil {
		return nil, fmt.Errorf("add rotated token to spoke %q: %w", req.SpokeID, err)
	}

	return &RotationResult{NewToken: newToken}, nil
}
