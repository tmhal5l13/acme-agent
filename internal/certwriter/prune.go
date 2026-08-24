package certwriter

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// keepVersions is how many of the most recent versions under
// dir/versions/ Prune keeps, beyond whichever one "current" points at
// (which is always kept regardless of age or count - see below). Not
// configurable: at roughly one renewal every 60-90 days, the exact number
// barely matters in practice, and a fixed default keeps this package's
// public surface (and this PR) small. Revisit if that stops being true.
const keepVersions = 3

// Prune deletes old version directories under dir/versions/, keeping the
// keepVersions most recent plus whichever one "current" currently points
// at (even if it isn't among the most recent by name - current is what
// Write's caller actually has installed, and must never be removed out
// from under it regardless of how Prune's own bookkeeping runs).
//
// Write itself never calls this - see its doc comment on why old versions
// accumulate by default. Callers that want bounded history call Prune
// themselves after a successful Write, the same way
// internal/spokeagent.Agent.ProcessCert does.
func Prune(dir string) error {
	versionsDir := filepath.Join(dir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", versionsDir, err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keepVersions {
		return nil
	}

	// Version directory names are <YYYYMMDDTHHMMSS>-<8hex> (see Write) -
	// the fixed-width timestamp prefix sorts lexically in the same order
	// as chronologically, so a plain string sort is enough to find the
	// newest without parsing anything back into a time.Time.
	sort.Strings(names)

	currentVersion, err := readCurrentVersion(dir)
	if err != nil {
		return fmt.Errorf("read current version: %w", err)
	}

	keep := make(map[string]bool, keepVersions+1)
	for _, name := range names[len(names)-keepVersions:] {
		keep[name] = true
	}
	keep[currentVersion] = true

	for _, name := range names {
		if keep[name] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(versionsDir, name)); err != nil {
			return fmt.Errorf("remove old version %s: %w", name, err)
		}
	}

	return nil
}
