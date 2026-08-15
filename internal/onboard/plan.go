// Package onboard generates the matching hub-config snippet and spoke
// config.yaml needed to add one certificate to one spoke, so the two never
// drift out of sync by hand-editing — the actual failure mode this exists
// to prevent (a typo'd cert name between the two files silently produces a
// 403 the first time the spoke tries to use it).
package onboard

import (
	"fmt"
	"strings"

	"acme-agent/config"
)

// Request describes the certificate being onboarded.
type Request struct {
	SpokeID     string
	CertName    string
	Domains     []string
	DNSProvider string // must already exist in the hub's dns_providers
	HubURL      string
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

	existing, spokeExists := hubCfg.Spokes[req.SpokeID]

	var token string
	if spokeExists {
		for _, c := range existing.Certs {
			if c.Name == req.CertName {
				return nil, fmt.Errorf("spoke %q already has a certificate named %q", req.SpokeID, req.CertName)
			}
		}
		token = existing.Token
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
		fmt.Fprintf(&b, "    token: \"${%s}\"\n", envVar)
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
	fmt.Fprintf(&b, "data_dir: /var/lib/acme-client\n\n")
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
