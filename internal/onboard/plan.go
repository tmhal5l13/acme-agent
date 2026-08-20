// Package onboard generates the matching hub-config snippet and spoke
// config.yaml needed to add one certificate to one spoke, so the two never
// drift out of sync by hand-editing — the actual failure mode this exists
// to prevent (a typo'd cert name between the two files silently produces a
// 403 the first time the spoke tries to use it).
package onboard

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tmhal5l13/acme-agent/config"
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

// Result is everything generated for the operator to apply — Plan never
// modifies hubCfg or any file itself.
type Result struct {
	Token      string // bearer token: freshly generated for a new spoke, reused for an existing one
	IsNewSpoke bool

	// HubEnvVarName is the ${VAR} name referenced in HubConfigYAML — only
	// meaningful when IsNewSpoke (an existing spoke's token, and therefore
	// its env var, doesn't change when adding another certificate).
	HubEnvVarName string

	HubConfigYAML   string // snippet to paste into the hub's config.yaml
	SpokeConfigYAML string // this spoke's complete config.yaml
}

// Plan validates req against the hub's current config — spoke/cert name
// collisions, and that DNSProvider actually exists — and produces a
// Result. A new spoke gets a fresh cryptographically random token; adding
// a certificate to a spoke that already exists reuses its existing token
// rather than generating (and thereby invalidating) a new one.
func Plan(hubCfg *config.HubConfig, req Request) (*Result, error) {
	if req.SpokeID == "" {
		return nil, fmt.Errorf("spoke id is required")
	}
	if req.CertName == "" {
		return nil, fmt.Errorf("cert name is required")
	}
	if len(req.Domains) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}
	if req.DNSProvider == "" {
		return nil, fmt.Errorf("dns provider is required")
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
	if _, ok := hubCfg.DNSProviders[req.DNSProvider]; !ok {
		return nil, fmt.Errorf("dns_provider %q is not defined in the hub's config under dns_providers — add it there first", req.DNSProvider)
	}

	domainSet := make(map[string]bool, len(req.Domains))
	for _, d := range req.Domains {
		domainSet[d] = true
	}
	for domain, provider := range req.DomainDNSProviders {
		if !domainSet[domain] {
			return nil, fmt.Errorf("domain_dns_providers references domain %q, which is not in Domains", domain)
		}
		if _, ok := hubCfg.DNSProviders[provider]; !ok {
			return nil, fmt.Errorf("domain_dns_providers[%s]: dns_provider %q is not defined in the hub's config under dns_providers — add it there first", domain, provider)
		}
	}

	existing, spokeExists := hubCfg.Spokes[req.SpokeID]

	var token string
	if spokeExists {
		for _, c := range existing.Certs {
			if c.Name == req.CertName {
				return nil, fmt.Errorf("spoke %q already has a certificate named %q", req.SpokeID, req.CertName)
			}
		}
		if len(existing.Tokens) == 0 {
			return nil, fmt.Errorf("spoke %q has no tokens configured on the hub — this shouldn't be possible for an already-valid hub config", req.SpokeID)
		}
		token = existing.Tokens[0] // the primary/first token; see PlanRotation for adding a second during rotation
	} else {
		t, err := GenerateToken()
		if err != nil {
			return nil, err
		}
		token = t
	}

	envVar := envVarName(req.SpokeID)

	return &Result{
		Token:           token,
		IsNewSpoke:      !spokeExists,
		HubEnvVarName:   envVar,
		HubConfigYAML:   buildHubConfigYAML(req, envVar, !spokeExists),
		SpokeConfigYAML: buildSpokeConfigYAML(req, existing.Certs),
	}, nil
}

func envVarName(spokeID string) string {
	sanitized := strings.NewReplacer("-", "_", " ", "_").Replace(spokeID)
	return "SPOKE_" + strings.ToUpper(sanitized) + "_TOKEN"
}

func buildHubConfigYAML(req Request, envVar string, isNewSpoke bool) string {
	var b strings.Builder
	if isNewSpoke {
		fmt.Fprintf(&b, "  %s:\n", req.SpokeID)
		fmt.Fprintf(&b, "    tokens:\n")
		fmt.Fprintf(&b, "      - \"${%s}\"\n", envVar)
		fmt.Fprintf(&b, "    certs:\n")
		writeCertBlock(&b, req, "      ")
	} else {
		fmt.Fprintf(&b, "  # add under spokes.%s.certs:\n", req.SpokeID)
		writeCertBlock(&b, req, "  ")
	}
	return b.String()
}

func writeCertBlock(b *strings.Builder, req Request, indent string) {
	fmt.Fprintf(b, "%s- name: %s\n", indent, req.CertName)
	fmt.Fprintf(b, "%s  domains: [%s]\n", indent, strings.Join(req.Domains, ", "))
	fmt.Fprintf(b, "%s  dns_provider: %s\n", indent, req.DNSProvider)
	if len(req.DomainDNSProviders) > 0 {
		// Sorted rather than range order, which Go randomizes per-run —
		// this snippet gets pasted/logged/diffed by a human, and stable
		// output matters more here than it would for machine-only YAML.
		domains := make([]string, 0, len(req.DomainDNSProviders))
		for d := range req.DomainDNSProviders {
			domains = append(domains, d)
		}
		sort.Strings(domains)
		fmt.Fprintf(b, "%s  domain_dns_providers:\n", indent)
		for _, d := range domains {
			fmt.Fprintf(b, "%s    %s: %s\n", indent, d, req.DomainDNSProviders[d])
		}
	}
}

// buildSpokeConfigYAML emits every certificate this spoke will manage, not
// just the one being added: existingCerts (the spoke's other certs, already
// on the hub) plus req's new one. Without this, regenerating the config for
// an existing spoke's second or third certificate would silently produce a
// spoke config.yaml that only lists the newest cert, dropping the others
// from local management entirely.
//
// existingCerts carries no reload_hook — that field is spoke-local only
// (see SpokeLocalCertConfig) and never appears in the hub's own config, so
// Plan has no way to know what an existing cert's hook already is. Those
// entries get the same commented-out placeholder a fresh cert with no
// ReloadHook gets; the operator re-adds the real command by hand.
func buildSpokeConfigYAML(req Request, existingCerts []config.SpokeCertConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "hub_url: %q\n", req.HubURL)
	fmt.Fprintf(&b, "hub_token: \"${HUB_TOKEN}\"\n")
	fmt.Fprintf(&b, "hub_tls_cert_file: %q # copy from the hub's data_dir/tls/cert.pem — verify its printed sha256 fingerprint matches\n\n", req.HubTLSCertFile)
	fmt.Fprintf(&b, "acme:\n")
	fmt.Fprintf(&b, "  environment: %s\n", req.ACMEEnv)
	fmt.Fprintf(&b, "  email: %s\n\n", req.ACMEEmail)
	fmt.Fprintf(&b, "data_dir: /var/lib/acme-spoke\n\n")
	fmt.Fprintf(&b, "certs:\n")
	for _, c := range existingCerts {
		fmt.Fprintf(&b, "  - name: %s\n", c.Name)
		fmt.Fprintf(&b, "    domains: [%s]\n", strings.Join(c.Domains, ", "))
		fmt.Fprintf(&b, "    # reload_hook: \"systemctl reload nginx\" # carry over this cert's real hook from its previous config.yaml — not visible from the hub's config\n")
	}
	fmt.Fprintf(&b, "  - name: %s\n", req.CertName)
	fmt.Fprintf(&b, "    domains: [%s]\n", strings.Join(req.Domains, ", "))
	if req.ReloadHook != "" {
		fmt.Fprintf(&b, "    reload_hook: %q\n", req.ReloadHook)
	} else {
		fmt.Fprintf(&b, "    # reload_hook: \"systemctl reload nginx\"\n")
	}
	return b.String()
}

// RotationRequest identifies the spoke whose bearer token is being
// rotated.
type RotationRequest struct {
	SpokeID string
}

// RotationResult is what PlanRotation generates: a freshly minted token
// to add *alongside* the spoke's existing one(s), plus the operator
// instructions for using it — see PlanRotation's doc comment for the full
// workflow this is one step of.
type RotationResult struct {
	NewToken      string
	HubEnvVarName string // ${VAR} name for NewToken
	HubConfigYAML string // instructions + snippet to add under spokes.<id>.tokens
}

// PlanRotation generates a new token for an already-configured spoke,
// without touching or even displaying its existing token(s) — see this
// package's doc comment on the general principle (never let hub/spoke
// config drift from hand-editing), applied here to rotation specifically.
//
// It deliberately does NOT attempt to reprint the spoke's full tokens:
// list including its current entries: by the time hubCfg is loaded,
// ${VAR} references have already been expanded to literal secret values
// (see config.expandEnv) — there's no way to recover what ${VAR} name an
// existing token was originally written as, and printing the literal
// secret value itself into a snippet meant for pasting/logging would be
// a real way to leak it. Instead this only describes what to *add*.
//
// The full rotation workflow this is one step of: (1) call PlanRotation,
// add the printed line to the hub's config.yaml and the matching env var
// to its env file, restart the hub - both tokens are now valid; (2) update
// the spoke's own hub_token to the new value, restart the spoke, confirm
// it's working; (3) remove the old token line from the hub's config.yaml
// and its env file, restart the hub again to complete the rotation.
func PlanRotation(hubCfg *config.HubConfig, req RotationRequest) (*RotationResult, error) {
	if req.SpokeID == "" {
		return nil, fmt.Errorf("spoke id is required")
	}
	if _, ok := hubCfg.Spokes[req.SpokeID]; !ok {
		return nil, fmt.Errorf("spoke %q is not defined in the hub's config", req.SpokeID)
	}

	newToken, err := GenerateToken()
	if err != nil {
		return nil, err
	}

	suffix, err := randomHex(4)
	if err != nil {
		return nil, fmt.Errorf("generate env var suffix: %w", err)
	}
	// A plain envVarName(req.SpokeID) would collide with the existing
	// token's env var name - these need to coexist as two distinct
	// ${VAR} references while both are valid during the grace period.
	envVar := envVarName(req.SpokeID) + "_" + strings.ToUpper(suffix)

	return &RotationResult{
		NewToken:      newToken,
		HubEnvVarName: envVar,
		HubConfigYAML: fmt.Sprintf(
			"  # Add this new token under spokes.%s.tokens - keep the existing\n"+
				"  # entry there too until the spoke has confirmed using the new one:\n"+
				"  #   - \"${%s}\"\n",
			req.SpokeID, envVar),
	}, nil
}
