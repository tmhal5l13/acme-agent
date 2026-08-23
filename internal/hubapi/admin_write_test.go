package hubapi

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/tmhal5l13/acme-agent/config"
)

// doAdminWriteRequest issues a real form-encoded POST against an admin
// write endpoint, with HTTP Basic Auth and (unless password=="") a
// same-origin Origin header - the two checks adminWriteGuard requires.
// req.Host and Origin's host are both fixed to adminTestHost, so a
// caller wanting to prove the Origin check itself rejects a mismatch
// only needs to override the origin argument.
const adminTestHost = "hub.example.com"

func doAdminWriteRequest(s *Server, path, password, origin string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRecorder()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Host = adminTestHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if password != "" {
		req.SetBasicAuth("admin", password)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	s.Handler().ServeHTTP(r, req)
	return r
}

func doAdminWrite(s *Server, path string, form url.Values) *httptest.ResponseRecorder {
	return doAdminWriteRequest(s, path, "status-token", "https://"+adminTestHost, form)
}

func TestAdminCreateSpoke_Succeeds(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	if err := s.store.UpsertDNSProvider("route53_main", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("seed dns provider: %v", err)
	}

	resp := doAdminWrite(s, "/admin/spokes", url.Values{
		"spoke_id": {"new-spoke"}, "cert_name": {"new-cert"},
		"domains": {"new.example.com"}, "dns_provider": {"route53_main"},
	})
	if resp.Code != 200 {
		t.Fatalf("got status %d, want 200, body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "new-spoke") {
		t.Errorf("one-time token page missing spoke id:\n%s", resp.Body.String())
	}

	got, err := s.store.GetSpoke("new-spoke")
	if err != nil {
		t.Fatalf("GetSpoke: %v", err)
	}
	if len(got.Tokens) != 1 || len(got.Certs) != 1 || got.Certs[0].Name != "new-cert" {
		t.Errorf("got %+v, want one token and one cert named new-cert", got)
	}
}

func TestAdminCreateSpoke_MissingFieldRejected(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	resp := doAdminWrite(s, "/admin/spokes", url.Values{"spoke_id": {"new-spoke"}})
	if resp.Code != 400 {
		t.Fatalf("got status %d, want 400", resp.Code)
	}
	if exists, _ := s.store.SpokeExists("new-spoke"); exists {
		t.Error("spoke was created despite missing required fields")
	}
}

func TestAdminCreateSpoke_DuplicateIDRejected(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	if err := s.store.UpsertDNSProvider("route53_main", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("seed dns provider: %v", err)
	}
	if err := s.store.CreateSpoke("dup-spoke", "existing-token"); err != nil {
		t.Fatalf("seed spoke: %v", err)
	}

	resp := doAdminWrite(s, "/admin/spokes", url.Values{
		"spoke_id": {"dup-spoke"}, "cert_name": {"cert-x"},
		"domains": {"x.example.com"}, "dns_provider": {"route53_main"},
	})
	if resp.Code != 409 {
		t.Fatalf("got status %d, want 409", resp.Code)
	}
}

func TestAdminCreateSpoke_WrongOriginRejected(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	resp := doAdminWriteRequest(s, "/admin/spokes", "status-token", "https://evil.example.com", url.Values{
		"spoke_id": {"new-spoke"}, "cert_name": {"new-cert"},
		"domains": {"new.example.com"}, "dns_provider": {"route53_main"},
	})
	if resp.Code != 403 {
		t.Fatalf("got status %d, want 403", resp.Code)
	}
	if exists, _ := s.store.SpokeExists("new-spoke"); exists {
		t.Error("spoke was created despite a cross-origin request")
	}
}

func TestAdminCreateSpoke_MissingOriginRejected(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	resp := doAdminWriteRequest(s, "/admin/spokes", "status-token", "", url.Values{
		"spoke_id": {"new-spoke"}, "cert_name": {"new-cert"},
		"domains": {"new.example.com"}, "dns_provider": {"route53_main"},
	})
	if resp.Code != 403 {
		t.Fatalf("got status %d, want 403", resp.Code)
	}
}

func TestAdminCreateSpoke_NoAuthRejected(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	resp := doAdminWriteRequest(s, "/admin/spokes", "", "https://"+adminTestHost, url.Values{
		"spoke_id": {"new-spoke"}, "cert_name": {"new-cert"},
		"domains": {"new.example.com"}, "dns_provider": {"route53_main"},
	})
	if resp.Code != 401 {
		t.Fatalf("got status %d, want 401", resp.Code)
	}
}

// TestAdminCreateSpoke_TakesEffectImmediatelyWithoutReload is the actual
// point of this PR: create via POST, then hit an authenticated spoke
// endpoint with the freshly-created token in the same test, with no
// s.Reload call from the test itself - proving the handler's own
// in-process reload (reloadAfterAdminWrite) is what made it live.
func TestAdminCreateSpoke_TakesEffectImmediatelyWithoutReload(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	if err := s.store.UpsertDNSProvider("route53_main", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("seed dns provider: %v", err)
	}

	resp := doAdminWrite(s, "/admin/spokes", url.Values{
		"spoke_id": {"live-spoke"}, "cert_name": {"live-cert"},
		"domains": {"live.example.com"}, "dns_provider": {"route53_main"},
	})
	if resp.Code != 200 {
		t.Fatalf("create: got status %d, want 200, body=%s", resp.Code, resp.Body.String())
	}
	const marker = "<pre>"
	idx := strings.Index(resp.Body.String(), marker)
	if idx == -1 {
		t.Fatalf("token page missing <pre> block:\n%s", resp.Body.String())
	}
	body := resp.Body.String()[idx+len(marker):]
	token := strings.TrimSpace(body[:strings.Index(body, "</pre>")])

	due := doRequest(s, "GET", "/v1/certs/live-cert/due", token, nil)
	if due.Code != 200 {
		t.Errorf("got status %d for the freshly-created spoke's own token, want 200 (no explicit reload was called)", due.Code)
	}
}

func TestAdminDeleteSpoke_Succeeds(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	if err := s.store.UpsertDNSProvider("route53_main", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("seed dns provider: %v", err)
	}
	if err := s.store.CreateSpoke("doomed-spoke", "doomed-token"); err != nil {
		t.Fatalf("seed spoke: %v", err)
	}

	resp := doAdminWrite(s, "/admin/spokes/doomed-spoke/delete", url.Values{})
	if resp.Code != 303 {
		t.Fatalf("got status %d, want 303", resp.Code)
	}
	if exists, _ := s.store.SpokeExists("doomed-spoke"); exists {
		t.Error("spoke still exists after delete")
	}
}

func TestAdminDeleteSpoke_UnknownSpokeReturns404(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	resp := doAdminWrite(s, "/admin/spokes/no-such-spoke/delete", url.Values{})
	if resp.Code != 404 {
		t.Fatalf("got status %d, want 404", resp.Code)
	}
}

func TestAdminAddSpokeToken_Succeeds(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	if err := s.store.CreateSpoke("rotate-spoke", "original-token"); err != nil {
		t.Fatalf("seed spoke: %v", err)
	}

	resp := doAdminWrite(s, "/admin/spokes/rotate-spoke/tokens", url.Values{})
	if resp.Code != 200 {
		t.Fatalf("got status %d, want 200, body=%s", resp.Code, resp.Body.String())
	}

	got, err := s.store.GetSpoke("rotate-spoke")
	if err != nil {
		t.Fatalf("GetSpoke: %v", err)
	}
	if len(got.Tokens) != 2 {
		t.Errorf("got %d tokens, want 2 (original plus rotated)", len(got.Tokens))
	}
}

func TestAdminRemoveSpokeToken_Succeeds(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	if err := s.store.CreateSpoke("rotate-spoke", "token-a"); err != nil {
		t.Fatalf("seed spoke: %v", err)
	}
	if err := s.store.AddSpokeToken("rotate-spoke", "token-b"); err != nil {
		t.Fatalf("seed second token: %v", err)
	}

	resp := doAdminWrite(s, "/admin/spokes/rotate-spoke/tokens/delete", url.Values{"token": {"token-a"}})
	if resp.Code != 303 {
		t.Fatalf("got status %d, want 303, body=%s", resp.Code, resp.Body.String())
	}

	got, err := s.store.GetSpoke("rotate-spoke")
	if err != nil {
		t.Fatalf("GetSpoke: %v", err)
	}
	if len(got.Tokens) != 1 || got.Tokens[0] != "token-b" {
		t.Errorf("got tokens %v, want only token-b remaining", got.Tokens)
	}
}

func TestAdminRemoveSpokeToken_LastTokenRejected(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	if err := s.store.CreateSpoke("lone-token-spoke", "only-token"); err != nil {
		t.Fatalf("seed spoke: %v", err)
	}

	resp := doAdminWrite(s, "/admin/spokes/lone-token-spoke/tokens/delete", url.Values{"token": {"only-token"}})
	if resp.Code != 409 {
		t.Fatalf("got status %d, want 409", resp.Code)
	}
}

func TestAdminUpsertSpokeCert_CreatesAndEdits(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	if err := s.store.UpsertDNSProvider("route53_main", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("seed dns provider: %v", err)
	}
	if err := s.store.CreateSpoke("cert-spoke", "cert-spoke-token"); err != nil {
		t.Fatalf("seed spoke: %v", err)
	}

	resp := doAdminWrite(s, "/admin/spokes/cert-spoke/certs", url.Values{
		"cert_name": {"web-cert"}, "domains": {"web.example.com"}, "dns_provider": {"route53_main"},
	})
	if resp.Code != 303 {
		t.Fatalf("create: got status %d, want 303, body=%s", resp.Code, resp.Body.String())
	}

	// Re-submitting the same cert_name edits it in place.
	resp = doAdminWrite(s, "/admin/spokes/cert-spoke/certs", url.Values{
		"cert_name": {"web-cert"}, "domains": {"updated.example.com"}, "dns_provider": {"route53_main"},
	})
	if resp.Code != 303 {
		t.Fatalf("edit: got status %d, want 303, body=%s", resp.Code, resp.Body.String())
	}

	got, err := s.store.GetSpoke("cert-spoke")
	if err != nil {
		t.Fatalf("GetSpoke: %v", err)
	}
	if len(got.Certs) != 1 || got.Certs[0].Domains[0] != "updated.example.com" {
		t.Errorf("got certs %+v, want exactly one cert with the updated domain", got.Certs)
	}
}

func TestAdminUpsertSpokeCert_UnknownDNSProviderRejected(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	if err := s.store.CreateSpoke("cert-spoke", "cert-spoke-token"); err != nil {
		t.Fatalf("seed spoke: %v", err)
	}

	resp := doAdminWrite(s, "/admin/spokes/cert-spoke/certs", url.Values{
		"cert_name": {"web-cert"}, "domains": {"web.example.com"}, "dns_provider": {"does-not-exist"},
	})
	if resp.Code != 400 {
		t.Fatalf("got status %d, want 400", resp.Code)
	}
}

func TestAdminRemoveSpokeCert_Succeeds(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	if err := s.store.UpsertDNSProvider("route53_main", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("seed dns provider: %v", err)
	}
	if err := s.store.CreateSpoke("cert-spoke", "cert-spoke-token"); err != nil {
		t.Fatalf("seed spoke: %v", err)
	}
	if err := s.store.UpsertSpokeCert("cert-spoke", config.SpokeCertConfig{
		Name: "web-cert", Domains: []string{"web.example.com"}, DNSProvider: "route53_main",
	}); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	resp := doAdminWrite(s, "/admin/spokes/cert-spoke/certs/web-cert/delete", url.Values{})
	if resp.Code != 303 {
		t.Fatalf("got status %d, want 303, body=%s", resp.Code, resp.Body.String())
	}

	got, err := s.store.GetSpoke("cert-spoke")
	if err != nil {
		t.Fatalf("GetSpoke: %v", err)
	}
	if len(got.Certs) != 0 {
		t.Errorf("got certs %+v, want none remaining", got.Certs)
	}
}

func TestAdminUpsertDNSProvider_Succeeds(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)

	resp := doAdminWrite(s, "/admin/dns-providers", url.Values{
		"name": {"cloudflare_main"}, "type": {"cloudflare"}, "api_token": {"secret-value"},
	})
	if resp.Code != 303 {
		t.Fatalf("got status %d, want 303, body=%s", resp.Code, resp.Body.String())
	}

	all, err := s.store.AllDNSProviders()
	if err != nil {
		t.Fatalf("AllDNSProviders: %v", err)
	}
	got, ok := all["cloudflare_main"]
	if !ok || got.Type != "cloudflare" || got.APIToken != "secret-value" {
		t.Errorf("got %+v, want cloudflare_main/cloudflare/secret-value", all)
	}
}

func TestAdminRemoveDNSProvider_Succeeds(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	if err := s.store.UpsertDNSProvider("unused_provider", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("seed dns provider: %v", err)
	}

	resp := doAdminWrite(s, "/admin/dns-providers/unused_provider/delete", url.Values{})
	if resp.Code != 303 {
		t.Fatalf("got status %d, want 303, body=%s", resp.Code, resp.Body.String())
	}
	if exists, _ := s.store.DNSProviderExists("unused_provider"); exists {
		t.Error("provider still exists after delete")
	}
}

// TestAdminRemoveDNSProvider_RefusedWhileCertStillReferencesIt is the
// HTTP-level twin of hubstore's own TestRemoveDNSProvider_RefusedWhileReferencedAsDefault
// - proving the handler surfaces the store's ErrInUse as a useful 4xx,
// not a 500.
func TestAdminRemoveDNSProvider_RefusedWhileCertStillReferencesIt(t *testing.T) {
	s := newTestServer(t, statusTestConfig(), statusTestSpokes(), nil)
	if err := s.store.UpsertDNSProvider("busy_provider", config.DNSProviderConfig{Type: "route53"}); err != nil {
		t.Fatalf("seed dns provider: %v", err)
	}
	if err := s.store.CreateSpoke("busy-spoke", "busy-token"); err != nil {
		t.Fatalf("seed spoke: %v", err)
	}
	if err := s.store.UpsertSpokeCert("busy-spoke", config.SpokeCertConfig{
		Name: "busy-cert", Domains: []string{"busy.example.com"}, DNSProvider: "busy_provider",
	}); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	resp := doAdminWrite(s, "/admin/dns-providers/busy_provider/delete", url.Values{})
	if resp.Code != 409 {
		t.Fatalf("got status %d, want 409, body=%s", resp.Code, resp.Body.String())
	}
	if exists, _ := s.store.DNSProviderExists("busy_provider"); !exists {
		t.Error("provider was removed despite still being referenced")
	}
}

func TestAdminWriteRoutes_NotRegisteredWithoutStatusToken(t *testing.T) {
	cfg := testConfig() // StatusToken deliberately left empty
	s := newTestServer(t, cfg, statusTestSpokes(), nil)

	resp := doAdminWriteRequest(s, "/admin/spokes", "anything", "https://"+adminTestHost, url.Values{})
	if resp.Code != 404 {
		t.Fatalf("got status %d, want 404 when status_token is unset", resp.Code)
	}
}
