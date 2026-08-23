package hubapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tmhal5l13/acme-agent/config"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
	"github.com/tmhal5l13/acme-agent/internal/onboard"
)

// adminWriteGuard runs the two checks every admin write handler needs
// before touching the store: authorizeAdmin, then requireSameOrigin
// (CSRF defense - see its doc comment). Returns the loaded state if both
// pass; if ok is false, the guard has already written the error response
// and the caller should return immediately without writing anything
// further.
func (s *Server) adminWriteGuard(w http.ResponseWriter, r *http.Request) (state *hubState, ok bool) {
	state = s.state.Load()
	if !authorizeAdmin(w, r, state) {
		return nil, false
	}
	if !requireSameOrigin(w, r) {
		return nil, false
	}
	return state, true
}

// reloadAfterAdminWrite rebuilds hubState from the store immediately after
// a successful admin write, in-process - the property that makes a
// browser action live on the very next request, no SIGHUP involved (see
// ARCHITECTURE.md "Config hot-reload"). A failure here is logged, not
// surfaced as a request error: the write itself already succeeded and is
// durably in the store: the next SIGHUP (or the next admin write) will
// pick it up even if this particular in-process refresh failed.
func (s *Server) reloadAfterAdminWrite(cfg *config.HubConfig) {
	if err := s.Reload(cfg); err != nil {
		slog.Error("reload after admin write", "error", err)
	}
}

// writeAdminStoreError maps a hubstore error to the HTTP status that best
// describes it for a browser-facing admin action. Unmatched errors
// (mostly hubstore's own validation errors - e.g. "dns_provider is not
// defined" - which aren't sentinel-wrapped) are treated as bad input
// (400): in practice everything this package's store methods return that
// isn't one of the sentinels below is validation-shaped, not an infra
// failure, for the same reason internal/onboard's callers never needed a
// separate "internal error" path either.
func writeAdminStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, hubstore.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, hubstore.ErrAlreadyExists), errors.Is(err, hubstore.ErrTokenInUse),
		errors.Is(err, hubstore.ErrInUse), errors.Is(err, hubstore.ErrLastToken):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// handleAdminCreateSpoke creates a new spoke with one initial token and
// one initial certificate. Unlike every other admin write, this does not
// redirect to /admin on success - the freshly generated token is only
// ever shown here, in plaintext, once, so it renders a one-time
// confirmation page instead (see renderAdminNewTokenPage).
func (s *Server) handleAdminCreateSpoke(w http.ResponseWriter, r *http.Request) {
	state, ok := s.adminWriteGuard(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	spokeID := r.FormValue("spoke_id")
	certName := r.FormValue("cert_name")
	domains := splitAndTrim(r.FormValue("domains"))
	dnsProvider := r.FormValue("dns_provider")
	if spokeID == "" || certName == "" || len(domains) == 0 || dnsProvider == "" {
		http.Error(w, "spoke_id, cert_name, domains, and dns_provider are all required", http.StatusBadRequest)
		return
	}
	if err := config.ValidateCertName(certName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, d := range domains {
		if err := config.ValidateDomain(d); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	token, err := onboard.GenerateToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.CreateSpoke(spokeID, token); err != nil {
		writeAdminStoreError(w, err)
		return
	}
	if err := s.store.UpsertSpokeCert(spokeID, config.SpokeCertConfig{
		Name: certName, Domains: domains, DNSProvider: dnsProvider,
	}); err != nil {
		writeAdminStoreError(w, err)
		return
	}
	s.reloadAfterAdminWrite(state.cfg)
	renderAdminNewTokenPage(w, spokeID, token)
}

// handleAdminDeleteSpoke removes a spoke entirely - its tokens, certs,
// observed state, and any outstanding enrollment token (see
// hubstore.Store.DeleteSpoke).
func (s *Server) handleAdminDeleteSpoke(w http.ResponseWriter, r *http.Request) {
	state, ok := s.adminWriteGuard(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteSpoke(r.PathValue("id")); err != nil {
		writeAdminStoreError(w, err)
		return
	}
	s.reloadAfterAdminWrite(state.cfg)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleAdminAddSpokeToken is rotation's step 1: a fresh token added
// alongside the spoke's existing one(s). Renders the same one-time
// confirmation page handleAdminCreateSpoke does, for the same reason.
func (s *Server) handleAdminAddSpokeToken(w http.ResponseWriter, r *http.Request) {
	state, ok := s.adminWriteGuard(w, r)
	if !ok {
		return
	}
	spokeID := r.PathValue("id")

	token, err := onboard.GenerateToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.AddSpokeToken(spokeID, token); err != nil {
		writeAdminStoreError(w, err)
		return
	}
	s.reloadAfterAdminWrite(state.cfg)
	renderAdminNewTokenPage(w, spokeID, token)
}

// handleAdminRemoveSpokeToken is rotation's step 2 - refused by the store
// if it would leave the spoke with zero tokens.
func (s *Server) handleAdminRemoveSpokeToken(w http.ResponseWriter, r *http.Request) {
	state, ok := s.adminWriteGuard(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}
	if err := s.store.RemoveSpokeToken(r.PathValue("id"), token); err != nil {
		writeAdminStoreError(w, err)
		return
	}
	s.reloadAfterAdminWrite(state.cfg)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleAdminUpsertSpokeCert creates or edits one certificate on an
// existing spoke - the same endpoint doubles as both, matching
// hubstore.Store.UpsertSpokeCert's own upsert semantics.
func (s *Server) handleAdminUpsertSpokeCert(w http.ResponseWriter, r *http.Request) {
	state, ok := s.adminWriteGuard(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	certName := r.FormValue("cert_name")
	domains := splitAndTrim(r.FormValue("domains"))
	dnsProvider := r.FormValue("dns_provider")
	domainDNSProviders, err := parseDomainDNSProvidersForm(r.FormValue("domain_dns_providers"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if certName == "" || len(domains) == 0 || dnsProvider == "" {
		http.Error(w, "cert_name, domains, and dns_provider are all required", http.StatusBadRequest)
		return
	}
	if err := config.ValidateCertName(certName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, d := range domains {
		if err := config.ValidateDomain(d); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if err := s.store.UpsertSpokeCert(r.PathValue("id"), config.SpokeCertConfig{
		Name: certName, Domains: domains, DNSProvider: dnsProvider, DomainDNSProviders: domainDNSProviders,
	}); err != nil {
		writeAdminStoreError(w, err)
		return
	}
	s.reloadAfterAdminWrite(state.cfg)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleAdminRemoveSpokeCert removes one certificate assignment from a
// spoke.
func (s *Server) handleAdminRemoveSpokeCert(w http.ResponseWriter, r *http.Request) {
	state, ok := s.adminWriteGuard(w, r)
	if !ok {
		return
	}
	if err := s.store.RemoveSpokeCert(r.PathValue("id"), r.PathValue("name")); err != nil {
		writeAdminStoreError(w, err)
		return
	}
	s.reloadAfterAdminWrite(state.cfg)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleAdminUpsertDNSProvider creates or updates one named DNS provider.
// Every possible per-type field is accepted on the same form regardless
// of which type is selected (see the dashboard template) - the unused
// ones for a given type simply end up empty, exactly as if they'd been
// left blank in config.yaml before this moved to the database.
func (s *Server) handleAdminUpsertDNSProvider(w http.ResponseWriter, r *http.Request) {
	state, ok := s.adminWriteGuard(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	providerType := r.FormValue("type")
	if name == "" || providerType == "" {
		http.Error(w, "name and type are both required", http.StatusBadRequest)
		return
	}

	cfg := config.DNSProviderConfig{
		Type:            providerType,
		APIToken:        r.FormValue("api_token"),
		AccessKeyID:     r.FormValue("access_key_id"),
		SecretAccessKey: r.FormValue("secret_access_key"),
		SessionToken:    r.FormValue("session_token"),
		HostedZoneID:    r.FormValue("hosted_zone_id"),
		Region:          r.FormValue("region"),
		APIKey:          r.FormValue("api_key"),
		APISecret:       r.FormValue("api_secret"),
		APIURL:          r.FormValue("api_url"),
		ServerName:      r.FormValue("server_name"),
		Nameserver:      r.FormValue("nameserver"),
		TSIGKey:         r.FormValue("tsig_key"),
		TSIGSecret:      r.FormValue("tsig_secret"),
		TSIGAlgorithm:   r.FormValue("tsig_algorithm"),
	}
	if err := s.store.UpsertDNSProvider(name, cfg); err != nil {
		writeAdminStoreError(w, err)
		return
	}
	s.reloadAfterAdminWrite(state.cfg)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleAdminRemoveDNSProvider removes a named DNS provider - refused by
// the store while any spoke's certificate still references it.
func (s *Server) handleAdminRemoveDNSProvider(w http.ResponseWriter, r *http.Request) {
	state, ok := s.adminWriteGuard(w, r)
	if !ok {
		return
	}
	if err := s.store.RemoveDNSProvider(r.PathValue("name")); err != nil {
		writeAdminStoreError(w, err)
		return
	}
	s.reloadAfterAdminWrite(state.cfg)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// splitAndTrim splits a comma-separated form value into trimmed,
// non-empty parts - the same convention cmd/acme-onboard/cmd/acme-hub's
// -domains flag already uses.
func splitAndTrim(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// parseDomainDNSProvidersForm parses a "domain=provider,domain=provider"
// form value - the same convention acme-hub --generate-token's
// -domain-dns-providers flag already uses (see parseDomainDNSProviders
// in cmd/acme-hub/main.go; kept as a local copy here rather than shared,
// matching this project's existing precedent of small format-parsing
// helpers not being worth a shared package across a CLI and the hub
// itself).
func parseDomainDNSProvidersForm(s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}
	m := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		domain, provider, ok := strings.Cut(pair, "=")
		if !ok || domain == "" || provider == "" {
			return nil, fmt.Errorf("invalid domain_dns_providers pair %q, want domain=provider", pair)
		}
		m[domain] = provider
	}
	return m, nil
}
