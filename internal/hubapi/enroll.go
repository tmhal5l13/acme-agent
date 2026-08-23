package hubapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

type enrollRequest struct {
	Secret string `json:"secret"`
}

type enrollCertInfo struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

type enrollResponse struct {
	SpokeID     string           `json:"spoke_id"`
	BearerToken string           `json:"bearer_token"`
	Certs       []enrollCertInfo `json:"certs"`
}

// handleEnroll redeems a one-time enrollment secret (minted by
// `acme-hub --generate-token`) and hands back everything a new spoke
// needs to build its own config.yaml: its real bearer token and the
// certs/domains it's authorized for. Unlike every other handler in this
// package, this needs no bearer-token authorize() call at all - the
// secret itself is the credential, since a brand-new spoke has no bearer
// token yet to present.
//
// The sequence below matters: LookupEnrollmentToken (read-only) runs
// before RedeemEnrollmentToken (consumes the secret), specifically so a
// secret that's valid but whose spoke isn't in the hub's live config yet
// (the operator hasn't pasted the generated snippet and reloaded) is
// never burned on that attempt - the spoke can retry with the exact same
// secret once the operator finishes. Redeeming unconditionally on first
// contact would permanently strand that retry.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Secret == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()

	spokeID, bearerToken, ok, err := s.store.LookupEnrollmentToken(req.Secret, now)
	if err != nil {
		slog.Error("enroll: lookup token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		// Deliberately generic - doesn't distinguish "never existed" from
		// "expired" from "already redeemed", same information-minimization
		// instinct authorize's errUnauthorized already applies to bearer
		// tokens.
		http.Error(w, "invalid or expired enrollment token", http.StatusUnauthorized)
		return
	}

	state := s.state.Load()
	spoke, exists := state.cfg.Spokes[spokeID]
	if !exists {
		slog.Warn("enroll: spoke not yet in hub config", "spoke", spokeID)
		http.Error(w, "spoke not yet configured on the hub - add the printed hub-config snippet under spokes: and reload the hub (SIGHUP), then retry with the same token", http.StatusServiceUnavailable)
		return
	}

	redeemed, err := s.store.RedeemEnrollmentToken(req.Secret, now)
	if err != nil {
		slog.Error("enroll: redeem token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !redeemed {
		// Lost a race against a concurrent redemption of the same secret
		// in the window between the lookup above and this call - treat it
		// exactly like any other invalid/expired/already-redeemed secret.
		http.Error(w, "invalid or expired enrollment token", http.StatusUnauthorized)
		return
	}

	certs := make([]enrollCertInfo, 0, len(spoke.Certs))
	for _, c := range spoke.Certs {
		certs = append(certs, enrollCertInfo{Name: c.Name, Domains: c.Domains})
	}

	slog.Info("spoke enrolled", "spoke", spokeID)
	writeJSON(w, http.StatusOK, enrollResponse{
		SpokeID:     spokeID,
		BearerToken: bearerToken,
		Certs:       certs,
	})
}
