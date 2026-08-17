package hubapi

import (
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
func (s *Server) authorize(r *http.Request) (spokeID string, cert config.SpokeCertConfig, err error) {
	token, ok := bearerToken(r)
	if !ok {
		return "", config.SpokeCertConfig{}, errUnauthorized
	}

	spokeID, ok = s.tokenToSpoke[token]
	if !ok {
		return "", config.SpokeCertConfig{}, errUnauthorized
	}

	name := r.PathValue("name")
	for _, c := range s.cfg.Spokes[spokeID].Certs {
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
