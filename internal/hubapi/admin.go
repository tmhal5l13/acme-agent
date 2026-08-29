package hubapi

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/tmhal5l13/acme-agent/internal/hubstore"
)

var adminTmpl = template.Must(template.New("admin").Parse(adminTemplateSrc))
var adminTokenTmpl = template.Must(template.New("admin-token").Parse(adminTokenTemplateSrc))

// adminPageData is everything the dashboard template renders: observed
// certificate status (read-only, unchanged since the read-only phase) plus
// the full desired state (spokes and DNS providers) the write forms below
// act on - all read fresh from the same loaded hubState, so the page
// never shows a form pre-filled with data older than what it would
// actually be upserting.
type adminPageData struct {
	Entries      []statusEntry
	Spokes       []hubstore.Spoke
	DNSProviders []dnsProviderSummary
}

// dnsProviderSummary is a DNS provider's name and type only - never its
// credentials, which stay write-only from the browser's perspective (the
// add/update form is always blank; editing means re-submitting a whole
// new set of values, not amending stored ones the page never echoes back).
type dnsProviderSummary struct {
	Name string
	Type string
}

// adminTemplateSrc is an inline template rather than a separate file (via
// embed.FS or similar): this is one page with no separate CSS/JS/image
// assets to bundle, so a const string in this file is the simplest thing
// that works and stays trivially greppable/diffable in review. html/template
// (not text/template) is load-bearing, not incidental - it auto-escapes
// {{.LastError}} and any other field that can carry spoke-reported or
// operator-influenced text.
//
// Every write is a plain HTML form POST - Basic Auth credentials a
// browser has cached apply to a form POST exactly the same way they
// apply to the page load that rendered the form, so there's still no
// fetch/JS surface that would ever need to hold the credential itself
// (the read-only phase's original reasoning for no JS, unchanged here).
// Destructive actions (remove a spoke/token/provider) do use a plain
// inline onclick="confirm(...)" as a client-side safety prompt - it
// never touches auth or the network itself, only whether the browser's
// normal form submission proceeds, and degrades harmlessly (submits
// unconfirmed) if JS is disabled.
const adminTemplateSrc = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="30">
  <title>acme-hub admin</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 1rem; }
    th, td { text-align: left; padding: 0.4rem 0.8rem; border-bottom: 1px solid #ccc; }
    tr.status-failed { background: #fdd; }
    tr.status-unknown { background: #eee; color: #666; }
    section { margin-bottom: 2.5rem; }
    form.inline { display: inline; }
    form.card { border: 1px solid #ccc; padding: 1rem; max-width: 32rem; }
    form.card label { display: block; margin-top: 0.5rem; font-size: 0.9rem; }
    form.card input { width: 100%; box-sizing: border-box; }
    form.card button { margin-top: 1rem; }
    .muted { color: #666; font-size: 0.85rem; }
  </style>
</head>
<body>
  <h1>acme-hub &mdash; admin</h1>

  <section>
    <h2>Certificate status</h2>
    <table>
      <tr><th>Spoke</th><th>Cert</th><th>Status</th><th>Not After</th><th>Last Checkin</th><th>Failures</th><th>Last Error</th><th>Hook</th></tr>
      {{range .Entries}}
      <tr class="status-{{.Status}}">
        <td>{{.SpokeID}}</td>
        <td>{{.Name}}</td>
        <td>{{.Status}}</td>
        <td>{{.NotAfter}}</td>
        <td>{{.LastCheckinAt}}</td>
        <td>{{.ConsecutiveFailures}}</td>
        <td>{{.LastError}}</td>
        <td{{if .LastHookError}} class="status-failed"{{end}}>{{.LastHookError}}</td>
      </tr>
      {{end}}
    </table>
  </section>

  <section>
    <h2>DNS providers</h2>
    <table>
      <tr><th>Name</th><th>Type</th><th></th></tr>
      {{range .DNSProviders}}
      <tr>
        <td>{{.Name}}</td>
        <td>{{.Type}}</td>
        <td>
          <form class="inline" method="post" action="/admin/dns-providers/{{.Name}}/delete">
            <button type="submit" onclick="return confirm('Remove DNS provider {{.Name}}?')">Remove</button>
          </form>
        </td>
      </tr>
      {{end}}
    </table>

    <form class="card" method="post" action="/admin/dns-providers">
      <h3>Add / update a DNS provider</h3>
      <p class="muted">Editing an existing provider means re-entering all of its fields - stored credentials are never shown back here.</p>
      <label>Name <input name="name" required></label>
      <label>Type
        <select name="type" required>
          <option value="route53">route53</option>
          <option value="cloudflare">cloudflare</option>
          <option value="godaddy">godaddy</option>
          <option value="pdns">pdns</option>
          <option value="rfc2136">rfc2136</option>
        </select>
      </label>
      <p class="muted">Only fill in the fields for the selected type - the rest are ignored.</p>
      <label>cloudflare: API token <input name="api_token"></label>
      <label>route53: access key ID <input name="access_key_id"></label>
      <label>route53: secret access key <input name="secret_access_key" type="password"></label>
      <label>route53: session token (optional) <input name="session_token" type="password"></label>
      <label>route53: hosted zone ID (optional) <input name="hosted_zone_id"></label>
      <label>route53: region (optional) <input name="region"></label>
      <label>godaddy: API key <input name="api_key"></label>
      <label>godaddy: API secret <input name="api_secret" type="password"></label>
      <label>pdns: API URL <input name="api_url"></label>
      <label>pdns: server name (optional) <input name="server_name"></label>
      <label>rfc2136: nameserver (host:port) <input name="nameserver"></label>
      <label>rfc2136: TSIG key name <input name="tsig_key"></label>
      <label>rfc2136: TSIG secret <input name="tsig_secret" type="password"></label>
      <label>rfc2136: TSIG algorithm (optional) <input name="tsig_algorithm"></label>
      <button type="submit">Save</button>
    </form>
  </section>

  <section>
    <h2>Spokes</h2>
    {{range .Spokes}}
    <div class="card" style="border:1px solid #ccc; padding:1rem; margin-bottom:1rem; max-width:40rem;">
      <h3>{{.ID}}</h3>

      <p><strong>Tokens</strong></p>
      <ul>
        {{range .Tokens}}
        <li>
          <code>{{.}}</code>
          <form class="inline" method="post" action="/admin/spokes/{{$.ID}}/tokens/delete">
            <input type="hidden" name="token" value="{{.}}">
            <button type="submit" onclick="return confirm('Remove this token?')">Remove</button>
          </form>
        </li>
        {{end}}
      </ul>
      <form method="post" action="/admin/spokes/{{.ID}}/tokens">
        <button type="submit">Add a new token (rotation)</button>
      </form>

      <p><strong>Certificates</strong></p>
      <ul>
        {{range .Certs}}
        <li>
          {{.Name}} &mdash; {{range .Domains}}{{.}} {{end}}&mdash; {{.DNSProvider}}
          <form class="inline" method="post" action="/admin/spokes/{{$.ID}}/certs/{{.Name}}/delete">
            <button type="submit" onclick="return confirm('Remove certificate {{.Name}}?')">Remove</button>
          </form>
        </li>
        {{end}}
      </ul>
      <form class="card" method="post" action="/admin/spokes/{{.ID}}/certs">
        <p class="muted">Adding a cert name that already exists on this spoke edits it in place.</p>
        <label>Cert name <input name="cert_name" required></label>
        <label>Domains (comma-separated) <input name="domains" required></label>
        <label>DNS provider <input name="dns_provider" required></label>
        <label>Per-domain DNS provider overrides (optional, domain=provider,domain=provider) <input name="domain_dns_providers"></label>
        <button type="submit">Save certificate</button>
      </form>

      <form method="post" action="/admin/spokes/{{.ID}}/delete">
        <button type="submit" onclick="return confirm('Remove spoke {{.ID}} entirely, including all its tokens and certificates?')">Remove this spoke</button>
      </form>
    </div>
    {{end}}

    <form class="card" method="post" action="/admin/spokes">
      <h3>Add a new spoke</h3>
      <label>Spoke ID <input name="spoke_id" required></label>
      <label>First certificate name <input name="cert_name" required></label>
      <label>Domains (comma-separated) <input name="domains" required></label>
      <label>DNS provider <input name="dns_provider" required></label>
      <button type="submit">Create spoke</button>
    </form>
  </section>
</body>
</html>`

// adminTokenTemplateSrc is the one-time confirmation page
// handleAdminCreateSpoke/handleAdminAddSpokeToken render instead of
// redirecting straight back to /admin - the only moment a freshly
// generated spoke bearer token is ever shown in plaintext.
const adminTokenTemplateSrc = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>acme-hub admin &mdash; new token</title>
  <style>body { font-family: sans-serif; margin: 2rem; } pre { padding: 1rem; background: #eee; overflow-x: auto; }</style>
</head>
<body>
  <h1>Spoke {{.SpokeID}}: new token</h1>
  <p><strong>Copy this token now - it will not be shown again.</strong></p>
  <pre>{{.Token}}</pre>
  <p><a href="/admin">Back to dashboard</a></p>
</body>
</html>`

// adminTokenPageData is adminTokenTmpl's data.
type adminTokenPageData struct {
	SpokeID string
	Token   string
}

func renderAdminNewTokenPage(w http.ResponseWriter, spokeID, token string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminTokenTmpl.Execute(w, adminTokenPageData{SpokeID: spokeID, Token: token}); err != nil {
		slog.Error("render admin new-token page", "error", err)
	}
}

// handleAdminDashboard serves a read-only certificate status view plus
// the write forms in internal/hubapi/admin_write.go act on - the same
// desired state adminEntries merges against, read fresh on every request
// (no client-side JS, no separate fetch - see the page's own comment on
// why).
func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	state := s.state.Load()
	if !authorizeAdmin(w, r, state) {
		return
	}

	entries, err := s.adminEntries(state)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	spokes, err := s.store.AllSpokes()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	providerCfgs, err := s.store.AllDNSProviders()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	providers := make([]dnsProviderSummary, 0, len(providerCfgs))
	for name, cfg := range providerCfgs {
		providers = append(providers, dnsProviderSummary{Name: name, Type: cfg.Type})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := adminPageData{Entries: entries, Spokes: spokes, DNSProviders: providers}
	if err := adminTmpl.Execute(w, data); err != nil {
		slog.Error("render admin dashboard", "error", err)
	}
}
