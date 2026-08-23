package hubapi

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tmhal5l13/acme-agent/config"
)

var (
	// errUnauthorized: no valid bearer token at all — the caller isn't a
	// spoke this hub knows about.
	errUnauthorized = errors.New("unauthorized")
	// errForbidden: the token is a real spoke, but that spoke isn't
	// authorized to act on the requested certificate name. This is the
	// mechanism that stops spoke A from touching spoke B's domains.
	errForbidden = errors.New("forbidden")
)

// authorize resolves the request's bearer token to a spoke, then confirms
// that spoke is authorized (per the hub's config) to act on the
// certificate named in the request's {name} path value. Every handler
// calls this first — it's simultaneously authentication (is this a real
// spoke?) and authorization (is this spoke allowed to touch this cert?).
//
// The map lookup below is deliberately not a crypto/subtle.ConstantTimeCompare
// loop over every known token. That pattern exists to fix a specific
// timing-leak shape: a naive token == candidate comparison that
// short-circuits on the first mismatched byte, letting an attacker who
// can measure response timing recover a token one byte at a time. A Go
// map lookup doesn't have that shape — matching is by hash of the full
// key, not a byte-by-byte compare against each candidate — so there's no
// per-byte timing signal to leak in the first place, and switching to a
// linear constant-time scan would only add real cost (O(n) in the number
// of spokes per request) for a leak that isn't there.
func (s *Server) authorize(r *http.Request) (spokeID string, cert config.SpokeCertConfig, err error) {
	token, ok := bearerToken(r)
	if !ok {
		return "", config.SpokeCertConfig{}, errUnauthorized
	}

	state := s.state.Load()

	spokeID, ok = state.tokenToSpoke[token]
	if !ok {
		return "", config.SpokeCertConfig{}, errUnauthorized
	}

	name := r.PathValue("name")
	for _, c := range state.cfg.Spokes[spokeID].Certs {
		if c.Name == name {
			return spokeID, c, nil
		}
	}

	return "", config.SpokeCertConfig{}, errForbidden
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	token := strings.TrimPrefix(h, prefix)
	return token, token != ""
}

// authorizeAdmin checks HTTP Basic Auth's password field against
// state.cfg.StatusToken (username ignored/arbitrary, matching
// StatusToken's single-shared-secret model - see its doc comment).
// Same constant-time comparison handleStatus uses, for the same reason:
// exactly one valid value being compared directly, not a set being
// looked up. Unlike handleStatus, a failed attempt sets WWW-Authenticate
// so a browser shows its native login prompt - handleStatus deliberately
// doesn't, since it's a JSON API for curl/monitoring tools, not a
// browser tab.
func authorizeAdmin(w http.ResponseWriter, r *http.Request, state *hubState) bool {
	_, password, ok := r.BasicAuth()
	if !ok || len(password) != len(state.cfg.StatusToken) ||
		subtle.ConstantTimeCompare([]byte(password), []byte(state.cfg.StatusToken)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="acme-hub admin"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// writeAuthError maps authorize's sentinel errors to the right HTTP status.
func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnauthorized):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case errors.Is(err, errForbidden):
		http.Error(w, "forbidden", http.StatusForbidden)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("write json response", "error", err)
	}
}
