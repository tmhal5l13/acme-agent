// Package dnsprovider builds lego DNS-01 challenge.Provider implementations
// from acme-agent's config. Only the hub imports this package — it's the
// only thing that ever holds DNS provider credentials; spokes relay
// challenge tokens through the hub's API instead (see internal/hubapi and
// internal/hubclient), never touching a provider directly.
package dnsprovider

import (
	"fmt"
	"net/url"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/pdns"
	"github.com/go-acme/lego/v4/providers/dns/route53"

	"acme-agent/config"
)

// New builds the DNS-01 challenge.Provider for the given named provider
// config, dispatching on its Type field. This is the whole "pluggable DNS
// provider" mechanism: adding a new lego-supported DNS host later is a new
// case here plus an import, not a new abstraction.
func New(cfg config.DNSProviderConfig) (challenge.Provider, error) {
	switch cfg.Type {
	case "cloudflare":
		cfCfg := cloudflare.NewDefaultConfig()
		cfCfg.AuthToken = cfg.APIToken
		return cloudflare.NewDNSProviderConfig(cfCfg)

	case "route53":
		r53Cfg := route53.NewDefaultConfig()
		r53Cfg.HostedZoneID = cfg.HostedZoneID // optional; lego looks up the zone by domain if empty
		r53Cfg.Region = cfg.Region             // optional; falls back to the AWS SDK's own resolution if empty
		return route53.NewDNSProviderConfig(r53Cfg)

	case "godaddy":
		gdCfg := godaddy.NewDefaultConfig()
		gdCfg.APIKey = cfg.APIKey
		gdCfg.APISecret = cfg.APISecret
		return godaddy.NewDNSProviderConfig(gdCfg)

	case "pdns":
		hostURL, err := url.Parse(cfg.APIURL)
		if err != nil {
			return nil, fmt.Errorf("parse pdns api_url %q: %w", cfg.APIURL, err)
		}
		pdnsCfg := pdns.NewDefaultConfig()
		pdnsCfg.APIKey = cfg.APIKey
		pdnsCfg.Host = hostURL
		if cfg.ServerName != "" {
			pdnsCfg.ServerName = cfg.ServerName // else lego's own default of "localhost" applies
		}
		return pdns.NewDNSProviderConfig(pdnsCfg)

	default:
		return nil, fmt.Errorf("unknown dns provider type %q", cfg.Type)
	}
}
