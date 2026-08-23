package config

import (
	"fmt"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// HubConfig is the top-level shape of the hub's config.yaml — everything
// needed to start the process (listen_addr, data_dir, TLS, hooks,
// timeouts). Spokes and DNS providers — which spokes exist, their
// tokens, their cert/DNS-provider assignments, DNS provider credentials —
// are desired state managed through the hub's database
// (internal/hubstore) instead, not this file: see "Database-backed
// desired state" in ARCHITECTURE.md for why, and acme-hub --import-config
// for migrating an older config.yaml that still has spokes:/dns_providers:
// sections.
type HubConfig struct {
	ListenAddr   string             `yaml:"listen_addr"` // prefer a private/internal interface over a public one where your network allows it — see TLS below for why this isn't the primary security boundary
	DataDir      string             `yaml:"data_dir"`
	DBPath       string             `yaml:"db_path"` // optional; defaults under DataDir
	ACMEDefaults ACMEDefaultsConfig `yaml:"acme_defaults"`

	// LegacySpokes/LegacyDNSProviders exist only to detect a config file
	// still carrying the pre-cutover spokes:/dns_providers: keys — plain
	// yaml.Unmarshal silently ignores keys with no matching struct field,
	// so without these, such a file would load "successfully" while
	// silently ignoring desired state the operator thinks is in effect.
	// validate() rejects a non-empty one with a pointer to
	// --import-config, rather than leaving it silently ignored.
	LegacySpokes       yaml.Node `yaml:"spokes"`
	LegacyDNSProviders yaml.Node `yaml:"dns_providers"`

	// TLSCertFile/TLSKeyFile locate the hub's TLS certificate and key.
	// Both optional — if either is left blank, they default under DataDir
	// and, if no certificate exists there yet, one is self-signed on
	// first startup (see internal/selfsigned and cmd/acme-hub). Spokes
	// trust this exact certificate directly (internal/hubclient) rather
	// than a certificate authority, since the hub typically has no public
	// DNS name for a real CA to issue against.
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`

	// TLSHost is the address spokes actually dial — embedded as the
	// self-signed certificate's SAN (see internal/selfsigned), since Go's
	// TLS client verifies the presented certificate against the address it
	// dialed, not just whether the certificate is trusted. Optional —
	// defaults to ListenAddr's host portion, which is correct whenever
	// ListenAddr is itself a specific, dialable interface. It's only
	// required when ListenAddr is a wildcard bind (e.g. "0.0.0.0:8443",
	// listening on every interface) while spokes reach the hub through one
	// specific hostname or IP — that hostname belongs here instead, or the
	// generated certificate ends up issued for the meaningless identity
	// "0.0.0.0" and every spoke's TLS handshake fails.
	TLSHost string `yaml:"tls_host"`

	// NotifyHook is an optional shell command run when a certificate's
	// status transitions to "failed" (alert) or from "failed" back to
	// "active" (resolved) — see internal/hubapi's checkin handler for the
	// exact trigger. Empty disables notifications entirely. Invoked the
	// same way reload_hook is (internal/hook), with context passed via
	// environment variables (ACME_SPOKE, ACME_CERT, ACME_STATUS,
	// ACME_PREVIOUS_STATUS, ACME_ERROR, ACME_NOT_AFTER) rather than a
	// hardcoded notification backend, so the operator can point it at
	// mail, a webhook, ntfy.sh, or anything else.
	NotifyHook    string   `yaml:"notify_hook"`
	NotifyTimeout Duration `yaml:"notify_timeout"`

	// DNSProviderTimeout bounds how long the hub waits on a single
	// provider.Present/CleanUp call before giving up and returning an
	// error to the requesting spoke (internal/hubapi/dns01.go) — lego's
	// challenge.Provider interface takes no context, so there's no way to
	// cancel the call itself; this only stops the HTTP handler from
	// blocking indefinitely, it doesn't cancel the DNS provider request
	// still running in the background. Matches the spoke's own
	// DNS01Timeout default (3m, headroom beyond Route53's own ~2min
	// propagation wait) since both bound the same underlying call from
	// either side of the relay.
	DNSProviderTimeout Duration `yaml:"dns_provider_timeout"`

	// StatusToken, if set, gates GET /v1/status - a read-only, fleet-wide
	// view of every certificate's renewal health (status, failure streak,
	// last success, expiry). Deliberately separate from a spoke's own
	// bearer token: a spoke's token only ever authorizes it for its own
	// certificates (see internal/hubapi.authorize), which would defeat
	// the point of a fleet-wide dashboard - this is a second, distinct
	// credential for whoever should have that wider view (an operator,
	// a monitoring system), not tied to any one spoke. Left empty, the
	// endpoint doesn't exist at all (see internal/hubapi.Handler).
	StatusToken string `yaml:"status_token"`

	// WatchdogStaleAfter bounds how long a configured certificate can go
	// without a checkin before internal/hubapi.RunWatchdog fires
	// notify_hook — the case notifyIfTransitioned's checkin-triggered
	// alerts structurally can't catch: a spoke that can't reach the hub at
	// all has no way to report that fact to the one endpoint it can't
	// reach, so it looks identical to a healthy spoke with nothing due yet
	// until this fires. The hub can't know any individual spoke's actual
	// configured poll_interval (that's spoke-local config), so this is
	// necessarily one hub-wide threshold rather than a per-spoke one.
	// Default (2h) is comfortably longer than the spoke's own default
	// 15-minute poll_interval, so normal poll jitter or one slow pass
	// never trips it.
	WatchdogStaleAfter Duration `yaml:"watchdog_stale_after"`

	// RenewalLeaseDuration bounds how long handleDue's renewal-lease claim
	// (hubstore.Store.Claim) lasts before it self-expires, letting a new
	// attempt proceed even if the one that acquired it never checks in at
	// all (crashed mid-attempt, say) — see "Renewal lease/claim" in
	// ARCHITECTURE.md. Default (15m) is comfortably longer than a real
	// issue/renew cycle (ACME order, DNS-01 propagation, install) but
	// short enough that a genuinely crashed spoke doesn't block retries
	// for long.
	RenewalLeaseDuration Duration `yaml:"renewal_lease_duration"`
}

// ACMEDefaultsConfig holds renewal policy defaults, overridable per cert via
// SpokeCertConfig.RenewBefore.
type ACMEDefaultsConfig struct {
	RenewBefore Duration `yaml:"renew_before"`

	// RenewalJitter staggers exactly when each certificate starts being
	// considered due, so a fleet of certificates issued around the same
	// time doesn't all converge on renewing at the identical moment —
	// the same "randomized renewal" practice Let's Encrypt's own client
	// list requires, applied here at the hub (the scheduling authority)
	// rather than per-spoke. Each certificate gets a jitter amount in
	// [0, RenewalJitter) that's stable across checks (deterministically
	// derived from spoke+cert name, not re-rolled every request — an
	// unstable jitter would make "due" flip-flop between polls) and only
	// ever makes a certificate due *earlier*, never later — it can't cut
	// into the safety margin RenewBefore was set to guarantee.
	//
	// Left unset (zero), it defaults to defaultRenewalJitter like every
	// other Duration field in this config — there's deliberately no way
	// to fully disable it by setting 0, the same limitation every other
	// field here already has (this project treats the zero value as
	// "unset", not "explicitly disabled"). To make jitter negligible,
	// set a very small nonzero value instead.
	RenewalJitter Duration `yaml:"renewal_jitter"`
}

// SpokeEntry is one spoke's identity (its bearer tokens) and the
// certificates it's authorized to request/renew. Any token in Tokens is
// what a spoke presents on every API call; the hub looks up which spoke
// (and therefore which certs and domains) a request is authorized to act
// on purely from this map — a spoke can never request a DNS-01 change for
// a domain outside its own Certs list.
//
// Tokens is a list, not a single value, specifically to support rotation:
// during a rotation grace period, both the old and new token are valid
// simultaneously (see internal/onboard's PlanRotation), so a spoke can be
// switched over to the new one without a coordinated instant cutover.
// Under normal operation it holds exactly one.
type SpokeEntry struct {
	Tokens []string          `yaml:"tokens" json:"tokens"`
	Certs  []SpokeCertConfig `yaml:"certs" json:"certs"`
}

// SpokeCertConfig is one certificate a spoke is authorized to manage.
type SpokeCertConfig struct {
	Name    string   `yaml:"name" json:"name"`
	Domains []string `yaml:"domains" json:"domains"`

	// DNSProvider is which dns_providers entry relays DNS-01 for this
	// cert's domains — the default for every domain in Domains, and the
	// only provider used unless a domain has its own override in
	// DomainDNSProviders. Let's Encrypt (and ACME generally) authorizes
	// each SAN independently via its own DNS-01 challenge against that
	// domain's own authoritative DNS - it has no concept of "DNS
	// provider" at all, so nothing about the protocol requires every
	// domain on one certificate to share a DNS backend. This field alone
	// covers the overwhelmingly common case (every domain on one cert
	// really is on the same provider); DomainDNSProviders exists for the
	// rare case it isn't.
	DNSProvider string `yaml:"dns_provider" json:"dns_provider"`

	// DomainDNSProviders optionally overrides DNSProvider for specific
	// domains — keys must be entries already in Domains, values must be
	// entries already in the hub's dns_providers (both checked in
	// validate()). A domain not listed here uses DNSProvider like
	// normal. Optional and almost always empty; only needed when one
	// certificate's SAN list spans domains on genuinely different DNS
	// backends.
	DomainDNSProviders map[string]string `yaml:"domain_dns_providers" json:"domain_dns_providers,omitempty"`

	RenewBefore Duration `yaml:"renew_before" json:"renew_before,omitempty"` // optional; 0 means "use ACMEDefaults.RenewBefore"
}

const (
	defaultHubRenewBefore       = 30 * 24 * time.Hour
	defaultNotifyTimeout        = 30 * time.Second
	defaultRenewalJitter        = 48 * time.Hour
	defaultDNSProviderTimeout   = 3 * time.Minute
	defaultWatchdogStaleAfter   = 2 * time.Hour
	defaultRenewalLeaseDuration = 15 * time.Minute
)

// hubEnvFileName is the env file LoadHubConfig reads ${VAR} values from,
// by convention next to config.yaml itself (see deploy/acme-hub.service's
// EnvironmentFile= and install-hub.sh, which set up exactly this layout:
// /etc/acme-hub/config.yaml alongside /etc/acme-hub/acme-hub.env).
const hubEnvFileName = "acme-hub.env"

// LoadHubConfig reads, expands, parses, and validates the hub's config
// file. ${VAR} references are resolved from hubEnvFileName next to path,
// read fresh on every call - falling back to the process's own
// environment for anything not in that file, or for the whole lookup if
// the file doesn't exist at all (not every deployment necessarily uses
// one).
//
// Reading the file fresh, rather than relying on the process's own
// inherited environment, is what makes this safe to call again from
// hubapi.Server.Reload on every SIGHUP: environment variables are fixed
// at process exec time and can never gain a variable added afterward, no
// matter how many times the process re-parses its own config - so a
// spoke enrolled (or a DNS provider added) after the hub started would
// otherwise never become visible without a real restart. See
// ARCHITECTURE.md "Config hot-reload".
func LoadHubConfig(path string) (*HubConfig, error) {
	env, err := fileEnvSource(filepath.Join(filepath.Dir(path), hubEnvFileName))
	if err != nil {
		return nil, err
	}

	cfg, err := loadYAML[HubConfig](path, env)
	if err != nil {
		return nil, err
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func (c *HubConfig) applyDefaults() {
	if c.DBPath == "" {
		c.DBPath = filepath.Join(c.DataDir, "acme-hub.db")
	}
	if c.ACMEDefaults.RenewBefore == 0 {
		c.ACMEDefaults.RenewBefore = Duration(defaultHubRenewBefore)
	}
	if c.ACMEDefaults.RenewalJitter == 0 {
		c.ACMEDefaults.RenewalJitter = Duration(defaultRenewalJitter)
	}
	if c.NotifyTimeout == 0 {
		c.NotifyTimeout = Duration(defaultNotifyTimeout)
	}
	if c.DNSProviderTimeout == 0 {
		c.DNSProviderTimeout = Duration(defaultDNSProviderTimeout)
	}
	if c.WatchdogStaleAfter == 0 {
		c.WatchdogStaleAfter = Duration(defaultWatchdogStaleAfter)
	}
	if c.RenewalLeaseDuration == 0 {
		c.RenewalLeaseDuration = Duration(defaultRenewalLeaseDuration)
	}
	if c.TLSCertFile == "" {
		c.TLSCertFile = filepath.Join(c.DataDir, "tls", "cert.pem")
	}
	if c.TLSKeyFile == "" {
		c.TLSKeyFile = filepath.Join(c.DataDir, "tls", "key.pem")
	}
}

func (c *HubConfig) validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	if c.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}
	if !c.LegacySpokes.IsZero() {
		return fmt.Errorf("config.yaml still has a spokes: section - spokes are now managed through the hub's database, not this file; run acme-hub --import-config to migrate it, then remove this section")
	}
	if !c.LegacyDNSProviders.IsZero() {
		return fmt.Errorf("config.yaml still has a dns_providers: section - DNS providers are now managed through the hub's database, not this file; run acme-hub --import-config to migrate it, then remove this section")
	}

	return nil
}
