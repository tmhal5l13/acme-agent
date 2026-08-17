package hubapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tmhal5l13/acme-agent/internal/hook"
	"github.com/tmhal5l13/acme-agent/internal/hubstore"
)

type checkinRequest struct {
	Domains   []string  `json:"domains"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Serial    string    `json:"serial"`
	Status    string    `json:"status"`
	Error     string    `json:"error"`
}

// validate rejects a checkin that's malformed or internally inconsistent
// before it ever reaches storage — not a substitute for actually verifying
// the reported certificate (the hub has no independent way to confirm
// NotBefore/NotAfter/Serial correspond to a real certificate at all; that
// would need the spoke to submit the certificate itself, e.g. a SHA-256
// fingerprint, not just self-reported fields — see "Known gaps"). This
// only catches internally-inconsistent or nonsensical values: a status
// outside the two the real client ever sends, an "active" checkin with no
// serial, or a validity window that doesn't make sense on its own terms
// (not_before on or after not_after). "failed" intentionally isn't held to
// the same requirements — internal/spokeagent's fail() reports it with a
// zero NotBefore/NotAfter/Serial, since there's no newly-issued
// certificate to describe.
func (r checkinRequest) validate() error {
	if r.Status != "active" && r.Status != "failed" {
		return fmt.Errorf("status must be %q or %q, got %q", "active", "failed", r.Status)
	}
	if r.Status == "active" {
		if r.Serial == "" {
			return fmt.Errorf("serial is required when status is %q", "active")
		}
		if r.NotBefore.IsZero() || r.NotAfter.IsZero() {
			return fmt.Errorf("not_before and not_after are required when status is %q", "active")
		}
		if !r.NotBefore.Before(r.NotAfter) {
			return fmt.Errorf("not_before must be before not_after")
		}
	}
	return nil
}

// handleCheckin records what a spoke reports about one of its own
// certificates after an issuance/renewal attempt (successful or not).
func (s *Server) handleCheckin(w http.ResponseWriter, r *http.Request) {
	spokeID, cert, err := s.authorize(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}

	var req checkinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var checkinErr error
	if req.Error != "" {
		checkinErr = errors.New(req.Error)
	}

	// Fetch the prior status before overwriting it, so a notify_hook (if
	// configured) fires only on a *transition* into or out of "failed" —
	// not on every checkin — see notifyIfTransitioned.
	previous, err := s.store.Get(spokeID, cert.Name)
	previousStatus := "unknown"
	if err == nil {
		previousStatus = previous.Status
	} else if !errors.Is(err, hubstore.ErrNotFound) {
		slog.Error("checkin: load previous state", "spoke", spokeID, "name", cert.Name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.store.Checkin(spokeID, cert.Name, req.NotBefore, req.NotAfter, req.Serial, req.Status, checkinErr); err != nil {
		slog.Error("checkin", "spoke", spokeID, "name", cert.Name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("checkin", "spoke", spokeID, "name", cert.Name, "status", req.Status, "not_after", req.NotAfter)

	s.notifyIfTransitioned(r.Context(), spokeID, cert.Name, previousStatus, req)

	w.WriteHeader(http.StatusNoContent)
}

// notifyIfTransitioned runs the hub's configured notify_hook when a
// certificate's status changes to "failed" (alert) or from "failed" back
// to "active" (resolved). Deliberately not fired on every checkin — a
// spoke that's already failing will keep checking in "failed" on its own
// retry schedule, and re-notifying on each one would just be alert fatigue
// for no new information. Runs synchronously, bounded by NotifyTimeout, the
// same way a certificate's reload_hook runs bounded by HookTimeout — a
// slow notify command adds that much latency to this one checkin request,
// never more, and never blocks other requests (Go's http.Server handles
// each concurrently).
func (s *Server) notifyIfTransitioned(ctx context.Context, spokeID, certName, previousStatus string, req checkinRequest) {
	if s.cfg.NotifyHook == "" {
		return
	}

	transitioned := (previousStatus != "failed" && req.Status == "failed") ||
		(previousStatus == "failed" && req.Status == "active")
	if !transitioned {
		return
	}

	env := map[string]string{
		"ACME_SPOKE":           spokeID,
		"ACME_CERT":            certName,
		"ACME_STATUS":          req.Status,
		"ACME_PREVIOUS_STATUS": previousStatus,
		"ACME_ERROR":           req.Error,
		"ACME_NOT_AFTER":       req.NotAfter.Format(time.RFC3339),
	}
	if err := hook.RunWithEnv(ctx, s.cfg.NotifyHook, s.cfg.NotifyTimeout.Duration(), env); err != nil {
		slog.Error("notify hook failed", "spoke", spokeID, "name", certName, "error", err)
	}
}

type dueResponse struct {
	Due bool `json:"due"`
}

// handleDue answers a spoke's "should I renew this certificate now"
// question — the hub is the scheduling authority, deciding based on the
// certificate's last-reported expiry against this cert's renewal policy
// (SpokeCertConfig.RenewBefore, or the hub-wide default).
func (s *Server) handleDue(w http.ResponseWriter, r *http.Request) {
	spokeID, cert, err := s.authorize(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}

	renewBefore := cert.RenewBefore.Duration()
	if renewBefore == 0 {
		renewBefore = s.cfg.ACMEDefaults.RenewBefore.Duration()
	}
	// Jitter only ever widens the renewal window (renews *earlier*, never
	// later), so it can't erode the safety margin renewBefore guarantees —
	// see jitterFor and ACMEDefaultsConfig.RenewalJitter.
	renewBefore += jitterFor(spokeID, cert.Name, s.cfg.ACMEDefaults.RenewalJitter.Duration())

	state, err := s.store.Get(spokeID, cert.Name)
	due := true // never checked in for this cert => nothing issued yet => due
	if err == nil {
		due = !state.NotAfter.Valid || time.Until(state.NotAfter.Time) < renewBefore
	} else if !errors.Is(err, hubstore.ErrNotFound) {
		slog.Error("due check", "spoke", spokeID, "name", cert.Name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, dueResponse{Due: due})
}
