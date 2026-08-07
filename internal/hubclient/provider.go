package hubclient

import (
	"context"
	"net/http"
	"time"
)

type dns01Request struct {
	Domain  string `json:"domain"`
	Token   string `json:"token"`
	KeyAuth string `json:"key_auth"`
}

// DNS01Provider implements lego's challenge.Provider (Present/CleanUp) by
// relaying both calls through the hub for one specific certificate name,
// instead of talking to a real DNS API directly. This is the whole trick
// that keeps DNS provider credentials off the spoke: from lego's
// perspective (and internal/acmeclient.Issue, which drives it) this looks
// like any other DNS-01 provider.
//
// lego's challenge.Provider interface doesn't accept a context, so calls
// build their own via context.WithTimeout(context.Background(), Timeout) —
// Timeout should be generous enough to cover whatever the hub's actual DNS
// provider needs (e.g. Route53's own ~2-minute propagation wait), not just
// a "normal" API call.
type DNS01Provider struct {
	Client   *Client
	CertName string
	Timeout  time.Duration
}

func (p *DNS01Provider) Present(domain, token, keyAuth string) error {
	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()
	return p.Client.do(ctx, http.MethodPost, "/v1/certs/"+p.CertName+"/dns01/present",
		dns01Request{Domain: domain, Token: token, KeyAuth: keyAuth}, nil)
}

func (p *DNS01Provider) CleanUp(domain, token, keyAuth string) error {
	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()
	return p.Client.do(ctx, http.MethodPost, "/v1/certs/"+p.CertName+"/dns01/cleanup",
		dns01Request{Domain: domain, Token: token, KeyAuth: keyAuth}, nil)
}
