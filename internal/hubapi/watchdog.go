package hubapi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/tmhal5l13/acme-agent/internal/hook"
)

// watchdogState holds the in-memory bookkeeping RunWatchdog needs across
// passes: which certs are currently considered stale (so notify_hook
// fires once per stale spell, not once per pass — the same alert-fatigue
// concern notifyIfTransitioned already guards against on the checkin
// path), and how long a cert that's never checked in at all has been in
// that state. Deliberately in-memory, not persisted to hubstore: a hub
// restart clearing this just means at most one extra notification after
// restart for something still genuinely stale, not a real problem, and
// it avoids coupling this feature's state to hubstore's schema migration
// sequence.
type watchdogState struct {
	notified            map[string]bool
	neverCheckedInSince map[string]time.Time
}

func newWatchdogState() *watchdogState {
	return &watchdogState{
		notified:            make(map[string]bool),
		neverCheckedInSince: make(map[string]time.Time),
	}
}

// RunWatchdog periodically scans every configured certificate for staleness
// — see watchdogPass — until ctx is cancelled. Mirrors the exact ticker-loop
// shape internal/spokeagent.Agent.Run already uses for its own polling
// loop: an immediate first pass, then one pass per interval.
func (s *Server) RunWatchdog(ctx context.Context, interval time.Duration) {
	state := newWatchdogState()
	state.watchdogPass(ctx, s)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			state.watchdogPass(ctx, s)
		}
	}
}

// watchdogPass is what notifyIfTransitioned's checkin-triggered alerts
// can't catch: a spoke that cannot reach the hub at all has no way to
// report that fact to the one endpoint it can't reach, so from the hub's
// side it looks identical to a healthy spoke with nothing due yet. This
// scans every certificate in the hub's own config — reusing Store.All()
// rather than re-deriving its own enumeration query — and flags one as
// stale if either:
//   - it has a real last_checkin_at, but longer ago than
//     cfg.WatchdogStaleAfter (a spoke that was working, then went silent), or
//   - it has never checked in at all, and has been in that state (per this
//     watchdog's own in-memory tracking, since there's no real timestamp
//     to measure from) for longer than cfg.WatchdogStaleAfter — giving a
//     freshly onboarded spoke the same grace period before its first real
//     checkin that an already-reporting spoke gets between checkins,
//     rather than alerting on the very next pass after it's added to config.
func (state *watchdogState) watchdogPass(ctx context.Context, s *Server) {
	observed, err := s.store.All()
	if err != nil {
		slog.Error("watchdog: list cert states", "error", err)
		return
	}
	byKey := make(map[string]time.Time, len(observed))
	for _, cs := range observed {
		if cs.LastCheckinAt.Valid {
			byKey[cs.SpokeID+"/"+cs.Name] = cs.LastCheckinAt.Time
		}
	}

	staleAfter := s.cfg.WatchdogStaleAfter.Duration()
	now := time.Now()

	for spokeID, spoke := range s.cfg.Spokes {
		for _, cert := range spoke.Certs {
			key := spokeID + "/" + cert.Name

			lastCheckin, hasCheckedIn := byKey[key]
			var stale bool
			var reason string
			switch {
			case hasCheckedIn && now.Sub(lastCheckin) > staleAfter:
				stale = true
				reason = fmt.Sprintf("no checkin since %s (%s ago)", lastCheckin.Format(time.RFC3339), now.Sub(lastCheckin).Round(time.Second))
			case !hasCheckedIn:
				since, seen := state.neverCheckedInSince[key]
				if !seen {
					state.neverCheckedInSince[key] = now
					break
				}
				if now.Sub(since) > staleAfter {
					stale = true
					reason = fmt.Sprintf("never checked in, first seen %s ago", now.Sub(since).Round(time.Second))
				}
			}

			if hasCheckedIn {
				delete(state.neverCheckedInSince, key)
			}

			if stale {
				if !state.notified[key] {
					state.notify(ctx, s, spokeID, cert.Name, reason)
					state.notified[key] = true
				}
				continue
			}

			if state.notified[key] {
				state.notifyRecovered(ctx, s, spokeID, cert.Name)
				delete(state.notified, key)
			}
		}
	}
}

func (state *watchdogState) notify(ctx context.Context, s *Server, spokeID, certName, reason string) {
	if s.cfg.NotifyHook == "" {
		return
	}
	env := map[string]string{
		"ACME_SPOKE":           spokeID,
		"ACME_CERT":            certName,
		"ACME_STATUS":          "stale",
		"ACME_PREVIOUS_STATUS": "unknown",
		"ACME_REASON":          reason,
	}
	if err := hook.RunWithEnv(ctx, s.cfg.NotifyHook, s.cfg.NotifyTimeout.Duration(), env); err != nil {
		slog.Error("watchdog notify hook failed", "spoke", spokeID, "name", certName, "error", err)
	}
}

func (state *watchdogState) notifyRecovered(ctx context.Context, s *Server, spokeID, certName string) {
	if s.cfg.NotifyHook == "" {
		return
	}
	env := map[string]string{
		"ACME_SPOKE":           spokeID,
		"ACME_CERT":            certName,
		"ACME_STATUS":          "active",
		"ACME_PREVIOUS_STATUS": "stale",
	}
	if err := hook.RunWithEnv(ctx, s.cfg.NotifyHook, s.cfg.NotifyTimeout.Duration(), env); err != nil {
		slog.Error("watchdog recovery notify hook failed", "spoke", spokeID, "name", certName, "error", err)
	}
}
