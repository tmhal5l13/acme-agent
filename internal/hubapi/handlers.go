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
	// ConsecutiveFailures is the spoke's own local failure-streak count
	// (see internal/store.CertState.ConsecutiveFailures) for this
	// certificate, only meaningful when Status is "failed" — reported so
	// the hub can distinguish a cert's first hiccup from its fifteenth
	// consecutive failure, which "status: failed" alone can't.
	ConsecutiveFailures int `json:"consecutive_failures"`
	// HookStatus/HookError/HookAt report a reload_hook's own outcome,
	// entirely independent of Status above (a hook failure must never be
	// conflated with a renewal failure - see internal/hook). Omitted
	// entirely by a spoke's cert that has no reload_hook configured, or on
	// a checkin that isn't reporting a hook result at all (this field set
	// is only ever populated by spokeagent.reportHookResult, a second,
	// separate checkin from the one reporting Status). Before this field
	// existed, a spoke's hook outcome was recorded only in its own local
	// database - invisible to the hub, and therefore to the admin
	// dashboard and GET /v1/status, indefinitely.
	HookStatus string    `json:"hook_status,omitempty"` // "ok" or "failed"
	HookError  string    `json:"hook_error,omitempty"`
	HookAt     time.Time `json:"hook_at,omitempty"`
}

// maxPlausibleCertLifetime is a generous, not tight, upper bound on
// not_after - not_before: 398 days is the maximum lifetime any public CA
// is currently permitted to issue under the CA/Browser Forum's baseline
// requirements. A private CA reached via acme.directory_url/ca_cert_file
// could legitimately issue something longer, so this exists to catch an
// implausible value, not to enforce the public-CA ceiling as policy — see
// validate's doc comment for what specific risk this closes.
const maxPlausibleCertLifetime = 398 * 24 * time.Hour

// validate rejects a checkin that's malformed or internally inconsistent
// before it ever reaches storage — not a substitute for actually verifying
// the reported certificate (the hub has no independent way to confirm
// NotBefore/NotAfter/Serial correspond to a real certificate at all; that
// would need the spoke to submit the certificate itself, e.g. a SHA-256
// fingerprint, not just self-reported fields — see "Known gaps"). This
// only catches internally-inconsistent or nonsensical values: a status
// outside the two the real client ever sends, an "active" checkin with no
// serial, a validity window that doesn't make sense on its own terms
// (not_before on or after not_after), or one implausibly long. "failed"
// intentionally isn't held to the same requirements — internal/spokeagent's
// fail() reports it with a zero NotBefore/NotAfter/Serial, since there's
// no newly-issued certificate to describe.
//
// The implausible-lifetime check exists for a specific reason: a spoke
// with a stolen or leaked bearer token can report whatever it wants on an
// "active" checkin, and handleDue trusts the reported not_after verbatim
// to decide whether renewal is due. Without this check, reporting a
// not_after decades in the future would suppress renewal indefinitely.
// This doesn't fully close that gap — a spoke can still lie within the
// plausible range — but it defeats the specific far-future version of the
// attack at effectively no cost. See "Known gaps" for the fuller fix this
// stops short of (the hub independently verifying the reported fields
// against the certificate itself).
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
		if r.NotAfter.Sub(r.NotBefore) > maxPlausibleCertLifetime {
			return fmt.Errorf("not_after is %s after not_before, longer than any plausible certificate lifetime (%s)",
				r.NotAfter.Sub(r.NotBefore), maxPlausibleCertLifetime)
		}
	}
	if r.HookStatus != "" && r.HookStatus != "ok" && r.HookStatus != "failed" {
		return fmt.Errorf("hook_status must be %q or %q, got %q", "ok", "failed", r.HookStatus)
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

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var req checkinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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

	// CheckinActive and CheckinFailed are deliberately separate calls, not
	// one method branching internally on req.Status: a failed checkin must
	// never touch not_before/not_after/serial_number, which describe
	// whatever certificate the spoke actually has installed right now, not
	// the failed attempt — see CheckinFailed's own doc comment for why
	// conflating the two used to silently lose that information.
	if req.Status == "active" {
		err = s.store.CheckinActive(spokeID, cert.Name, req.NotBefore, req.NotAfter, req.Serial)
	} else {
		var checkinErr error
		if req.Error != "" {
			checkinErr = errors.New(req.Error)
		}
		err = s.store.CheckinFailed(spokeID, cert.Name, checkinErr, req.ConsecutiveFailures)
	}
	if err != nil {
		slog.Error("checkin", "spoke", spokeID, "name", cert.Name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// HookStatus is entirely independent of req.Status above (see the
	// field's own doc comment) - recorded separately, and only when a
	// checkin actually carries a hook result at all. Most checkins don't:
	// the one reporting a fresh issuance/renewal never does (see
	// spokeagent.ProcessCert, which reports the hook's outcome via a
	// second, separate checkin once the hook has actually run), and a
	// cert with no reload_hook configured never has one to report.
	if req.HookStatus != "" {
		var hookErr error
		if req.HookStatus == "failed" {
			hookErr = errors.New(req.HookError)
		}
		if err := s.store.MarkHookResult(spokeID, cert.Name, hookErr); err != nil {
			slog.Error("checkin: record hook result", "spoke", spokeID, "name", cert.Name, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	// req.NotAfter is only meaningful on an "active" checkin — a "failed"
	// one legitimately carries a zero value (the spoke's fail() never sets
	// it), but the certificate's real expiry didn't go anywhere; it's
	// exactly what CheckinFailed just preserved in storage. Re-fetch rather
	// than reason about which of req/previous applies, so the log line and
	// the notify hook below always reflect the one authoritative value —
	// this matters most on a transition into "failed", the moment an
	// accurate expiry is most useful to whoever the notify hook alerts.
	notAfter := req.NotAfter
	if current, getErr := s.store.Get(spokeID, cert.Name); getErr == nil && current.NotAfter.Valid {
		notAfter = current.NotAfter.Time
	}

	slog.Info("checkin", "spoke", spokeID, "name", cert.Name, "status", req.Status, "not_after", notAfter)

	s.notifyIfTransitioned(r.Context(), spokeID, cert.Name, previousStatus, req, notAfter)

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
func (s *Server) notifyIfTransitioned(ctx context.Context, spokeID, certName, previousStatus string, req checkinRequest, notAfter time.Time) {
	cfg := s.state.Load().cfg
	if cfg.NotifyHook == "" {
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
		"ACME_NOT_AFTER":       notAfter.Format(time.RFC3339),
	}
	if err := hook.RunWithEnv(ctx, cfg.NotifyHook, cfg.NotifyTimeout.Duration(), env); err != nil {
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
//
// Answering "due" also atomically claims a renewal lease
// (hubstore.Store.Claim) — the mechanism that stops two overlapping
// attempts for the same certificate from both proceeding at once (e.g.
// two processes of what's supposed to be one spoke running concurrently
// after a botched restart). If a claim is already held and unexpired,
// this reports "not due" even though it otherwise would be, so a second
// caller doesn't also start a real ACME order; the wire response shape
// (dueResponse{Due bool}) doesn't change at all to express this — from a
// caller's perspective, "due" already meant "yes, go ahead," and that
// remains exactly true, whether the reason is genuinely not due yet or
// someone else already has it claimed. The claim is released when a
// checkin eventually arrives (CheckinActive/CheckinFailed both do this
// unconditionally) or, failing that, once it self-expires after
// RenewalLeaseDuration.
func (s *Server) handleDue(w http.ResponseWriter, r *http.Request) {
	spokeID, cert, err := s.authorize(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}

	cfg := s.state.Load().cfg

	renewBefore := cert.RenewBefore.Duration()
	if renewBefore == 0 {
		renewBefore = cfg.ACMEDefaults.RenewBefore.Duration()
	}
	// Jitter only ever widens the renewal window (renews *earlier*, never
	// later), so it can't erode the safety margin renewBefore guarantees —
	// see jitterFor and ACMEDefaultsConfig.RenewalJitter.
	renewBefore += jitterFor(spokeID, cert.Name, cfg.ACMEDefaults.RenewalJitter.Duration())

	certState, err := s.store.Get(spokeID, cert.Name)
	due := true // never checked in for this cert => nothing issued yet => due
	if err == nil {
		due = !certState.NotAfter.Valid || time.Until(certState.NotAfter.Time) < renewBefore
	} else if !errors.Is(err, hubstore.ErrNotFound) {
		slog.Error("due check", "spoke", spokeID, "name", cert.Name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if due {
		claimed, err := s.store.Claim(spokeID, cert.Name, cfg.RenewalLeaseDuration.Duration())
		if err != nil {
			slog.Error("claim renewal lease", "spoke", spokeID, "name", cert.Name, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		due = claimed
	}

	writeJSON(w, http.StatusOK, dueResponse{Due: due})
}
