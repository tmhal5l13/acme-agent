package acmeclient

import (
	"fmt"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"

	"github.com/tmhal5l13/acme-agent/config"
)

// Issue obtains a new certificate for domains via DNS-01, using dnsProvider
// to present and clean up the TXT challenge record. The first domain becomes
// the certificate's CommonName; any others are added as Subject Alternative
// Names (this is how wildcard + apex, e.g. "example.com" + "*.example.com",
// end up on one certificate).
//
// challengeOpts customizes lego's DNS-01 challenge behavior (e.g.
// dns01.DisableCompletePropagationRequirement) if the caller needs it. In
// the hub-and-spoke architecture, dnsProvider is normally a spoke's
// internal/hubclient relay rather than a concrete backend — the spoke has
// no visibility into which DNS provider the hub actually uses for it (that
// stays hub-side, see internal/dnsprovider), so there's no provider
// identity to make a per-type decision on. Callers typically pass no
// options and get lego's default client-side propagation check.
//
// Bundle is left false so the returned Resource.Certificate is the leaf
// certificate alone — certwriter is responsible for assembling fullchain.pem
// from Certificate + IssuerCertificate, which keeps the on-disk file
// contents explicit rather than implicit in an SDK flag.
//
// acmeCfg is only consulted for CACertFile (see httpClientFor) — the same
// private-CA transport trust used for account registration applies equally
// here, since this is another round of calls to that same CA's API.
func Issue(user *User, caDirectoryURL string, acmeCfg config.ACMEConfig, dnsProvider challenge.Provider, domains []string, challengeOpts ...dns01.ChallengeOption) (*certificate.Resource, error) {
	cfg := lego.NewConfig(user)
	cfg.CADirURL = caDirectoryURL

	httpClient, err := httpClientFor(acmeCfg)
	if err != nil {
		return nil, err
	}
	if httpClient != nil {
		cfg.HTTPClient = httpClient
	}

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create ACME client: %w", err)
	}

	if err := client.Challenge.SetDNS01Provider(dnsProvider, challengeOpts...); err != nil {
		return nil, fmt.Errorf("configure DNS-01 provider: %w", err)
	}

	cert, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  false,
	})
	if err != nil {
		return nil, fmt.Errorf("obtain certificate: %w", err)
	}

	return cert, nil
}
