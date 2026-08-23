package hubapi

import (
	"html/template"
	"log/slog"
	"net/http"
)

var adminTmpl = template.Must(template.New("admin").Parse(adminTemplateSrc))

// adminTemplateSrc is an inline template rather than a separate file (via
// embed.FS or similar): this is one page with no separate CSS/JS/image
// assets to bundle, so a const string in this file is the simplest thing
// that works and stays trivially greppable/diffable in review. html/template
// (not text/template) is load-bearing, not incidental - it auto-escapes
// {{.LastError}} and any other field that can carry spoke-reported or
// operator-influenced text.
const adminTemplateSrc = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="30">
  <title>acme-hub admin</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; }
    table { border-collapse: collapse; width: 100%; }
    th, td { text-align: left; padding: 0.4rem 0.8rem; border-bottom: 1px solid #ccc; }
    tr.status-failed { background: #fdd; }
    tr.status-unknown { background: #eee; color: #666; }
  </style>
</head>
<body>
  <h1>acme-hub &mdash; certificate status</h1>
  <table>
    <tr><th>Spoke</th><th>Cert</th><th>Status</th><th>Not After</th><th>Last Checkin</th><th>Failures</th><th>Last Error</th></tr>
    {{range .}}
    <tr class="status-{{.Status}}">
      <td>{{.SpokeID}}</td>
      <td>{{.Name}}</td>
      <td>{{.Status}}</td>
      <td>{{.NotAfter}}</td>
      <td>{{.LastCheckinAt}}</td>
      <td>{{.ConsecutiveFailures}}</td>
      <td>{{.LastError}}</td>
    </tr>
    {{end}}
  </table>
</body>
</html>`

// handleAdminDashboard serves a read-only, server-rendered HTML view of
// the exact same fleet-wide data GET /v1/status reports as JSON (see
// adminEntries) - a human-readable twin, not a separate source of truth.
// No client-side JS: the page re-fetches itself via
// <meta http-equiv="refresh"> instead of polling, so this phase carries no
// JS/fetch surface that would need to hold the auth credential itself.
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

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminTmpl.Execute(w, entries); err != nil {
		slog.Error("render admin dashboard", "error", err)
	}
}
