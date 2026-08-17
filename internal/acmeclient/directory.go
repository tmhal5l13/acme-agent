package acmeclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/lego"

	"github.com/tmhal5l13/acme-agent/config"
)

// DirectoryURL resolves the ACME directory endpoint to use: cfg.DirectoryURL
// verbatim if set (any ACME-compliant CA, public or private), otherwise
// cfg.Environment mapped to Let's Encrypt's own two directory URLs. config's
// own validation guarantees exactly one of the two is set, so both the
// unknown-environment and both-set cases below are unreachable in practice
// - handled defensively anyway rather than trusting that invariant blindly
// this far from where it's enforced.
func DirectoryURL(cfg config.ACMEConfig) (string, error) {
	if cfg.DirectoryURL != "" {
		return cfg.DirectoryURL, nil
	}
	switch cfg.Environment {
	case "staging":
		return lego.LEDirectoryStaging, nil
	case "production":
		return lego.LEDirectoryProduction, nil
	default:
		return "", fmt.Errorf("unknown acme environment %q", cfg.Environment)
	}
}

// httpClientFor builds the *http.Client lego uses for its own outbound
// calls to the ACME server, trusting cfg.CACertFile in addition to the OS's
// normal trust store. This is a different trust relationship than the
// certificates this project requests from that CA: it's whether we trust
// the CA's own API endpoint's TLS certificate, which a public CA's already
// covers via the OS trust store, but a private CA's usually doesn't.
// Returns nil (lego's own default client, unchanged) when CACertFile is
// unset.
func httpClientFor(cfg config.ACMEConfig) (*http.Client, error) {
	if cfg.CACertFile == "" {
		return nil, nil
	}

	certPool, err := lego.CreateCertPool([]string{cfg.CACertFile}, true)
	if err != nil {
		return nil, fmt.Errorf("load ca_cert_file %q: %w", cfg.CACertFile, err)
	}

	return &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}, nil
}
