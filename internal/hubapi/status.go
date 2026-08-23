package hubapi

import (
	"crypto/subtle"
	"net/http"
	"sort"
	"time"

	"github.com/tmhal5l13/acme-agent/internal/hubstore"
)

// statusEntry is one certificate's renewal health as GET /v1/status
// reports it - hubstore.CertState's fields, flattened out of sql.Null*
// wrappers into plain JSON-friendly types (a zero time.Time / empty
// string standing in for "never happened" rather than a nested
// {Valid, Time} pair a dashboard consumer would have to unwrap itself).
type statusEntry struct {
	SpokeID             string    `json:"spoke_id"`
	Name                string    `json:"name"`
	Status              string    `json:"status"`
	Serial              string    `json:"serial,omitempty"`
	NotBefore           time.Time `json:"not_before,omitempty"`
	NotAfter            time.Time `json:"not_after,omitempty"`
	LastCheckinAt       time.Time `json:"last_checkin_at,omitempty"`
	LastSuccessAt       time.Time `json:"last_success_at,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
}

// handleStatus answers a read-only, fleet-wide view of every configured
// certificate's renewal health - unlike every other handler in this
// package, it isn't scoped to one spoke's own certificates (see
// HubConfig.StatusToken's doc comment on why that needs a separate
// credential). Merges observed state (internal/hubstore, what's actually
// been reported) with desired state (state.spokes, what's configured) so a
// certificate that's configured but has never once checked in still
// appears - as status "unknown", the same default hubstore itself uses -
// rather than silently missing from the response entirely.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	state := s.state.Load()

	token, ok := bearerToken(r)
	// subtle.ConstantTimeCompare here (unlike authorize's plain map
	// lookup for per-spoke tokens) because there's exactly one valid
	// value to compare against, not a set to look up in - a direct
	// token == state.cfg.StatusToken comparison is exactly the byte-by-byte
	// shape that leaks timing information about how much of the prefix
	// matched, which is the actual case this primitive exists for.
	if !ok || len(token) != len(state.cfg.StatusToken) ||
		subtle.ConstantTimeCompare([]byte(token), []byte(state.cfg.StatusToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	entries, err := s.adminEntries(state)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, entries)
}

// adminEntries merges observed state (s.store.All()) with desired state
// (state.spokes[*].Certs) into one deterministically-sorted slice - a
// configured-but-never-checked-in cert still appears as "unknown" rather
// than being silently missing. Shared by handleStatus (JSON) and
// handleAdminDashboard (HTML) so the two views can never structurally
// diverge on what counts.
func (s *Server) adminEntries(state *hubState) ([]statusEntry, error) {
	observed, err := s.store.All()
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]hubstore.CertState, len(observed))
	for _, cs := range observed {
		byKey[cs.SpokeID+"/"+cs.Name] = cs
	}

	var entries []statusEntry
	for spokeID, spoke := range state.spokes {
		for _, cert := range spoke.Certs {
			cs, ok := byKey[spokeID+"/"+cert.Name]
			if !ok {
				entries = append(entries, statusEntry{SpokeID: spokeID, Name: cert.Name, Status: "unknown"})
				continue
			}
			entries = append(entries, statusEntry{
				SpokeID:             spokeID,
				Name:                cert.Name,
				Status:              cs.Status,
				Serial:              cs.SerialNumber.String,
				NotBefore:           cs.NotBefore.Time,
				NotAfter:            cs.NotAfter.Time,
				LastCheckinAt:       cs.LastCheckinAt.Time,
				LastSuccessAt:       cs.LastSuccessAt.Time,
				LastError:           cs.LastError.String,
				ConsecutiveFailures: cs.ConsecutiveFailures,
			})
		}
	}
	// Deterministic order - map iteration above isn't, and a dashboard
	// diffing two responses over time (or a human reading raw output)
	// shouldn't see certificates reshuffle from one request to the next
	// with nothing having actually changed.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].SpokeID != entries[j].SpokeID {
			return entries[i].SpokeID < entries[j].SpokeID
		}
		return entries[i].Name < entries[j].Name
	})
	if entries == nil {
		entries = []statusEntry{}
	}
	return entries, nil
}
