package certwriter

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// makeVersion directly constructs a version directory named suffix (not
// through Write, whose real timestamp-based naming can't be controlled
// precisely enough for deterministic ordering assertions - see the
// package doc comment on Write's version-name format). Returns the
// version's directory name, always distinct and always sorting after any
// name built from a smaller n in the same test, which is all these tests
// need from "realistic" naming.
func makeVersion(t *testing.T, dir string, n int) string {
	t.Helper()
	name := fmt.Sprintf("20260101T000000-%08d", n)
	versionDir := filepath.Join(dir, "versions", name)
	if err := os.MkdirAll(versionDir, 0o750); err != nil {
		t.Fatalf("create version dir %s: %v", name, err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "cert.pem"), []byte("cert"), 0o644); err != nil {
		t.Fatalf("write cert.pem in %s: %v", name, err)
	}
	return name
}

// setCurrent repoints dir/current at version, the same atomic-rename
// pattern Write itself uses.
func setCurrent(t *testing.T, dir, version string) {
	t.Helper()
	currentPath := filepath.Join(dir, "current")
	_ = os.Remove(currentPath)
	if err := os.Symlink(filepath.Join("versions", version), currentPath); err != nil {
		t.Fatalf("set current to %s: %v", version, err)
	}
}

func listVersions(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "versions"))
	if err != nil {
		t.Fatalf("read versions dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestPrune_KeepsNewestN(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs", "example")

	var versions []string
	for i := 0; i < keepVersions+2; i++ {
		versions = append(versions, makeVersion(t, dir, i))
	}
	// n increases with i, so the highest-numbered (last-created) version
	// is also current, matching Write's real behavior of always pointing
	// current at whatever it just wrote.
	setCurrent(t, dir, versions[len(versions)-1])

	if err := Prune(dir); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	wantKept := make(map[string]bool, keepVersions)
	for _, v := range versions[len(versions)-keepVersions:] {
		wantKept[v] = true
	}

	got := listVersions(t, dir)
	if len(got) != keepVersions {
		t.Fatalf("got %d versions remaining, want %d", len(got), keepVersions)
	}
	for _, name := range got {
		if !wantKept[name] {
			t.Errorf("kept unexpected version %q, want only the %d newest", name, keepVersions)
		}
	}
}

// TestPrune_KeepsCurrentVersionRegardlessOfAge is the one case that must
// never regress: even if "current" points at a version outside the
// newest-N window, Prune must not delete it out from under whatever's
// reading dir/current right now.
func TestPrune_KeepsCurrentVersionRegardlessOfAge(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs", "example")

	var versions []string
	for i := 0; i < keepVersions+3; i++ {
		versions = append(versions, makeVersion(t, dir, i))
	}
	oldest := versions[0]
	setCurrent(t, dir, oldest) // deliberately outside the newest-N window

	if err := Prune(dir); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "versions", oldest)); err != nil {
		t.Errorf("oldest version %q was pruned even though current points at it: %v", oldest, err)
	}
	// keepVersions newest + the forced-old current = keepVersions+1 total.
	got := listVersions(t, dir)
	if len(got) != keepVersions+1 {
		t.Errorf("got %d versions remaining, want %d (the %d newest plus the forced-old current)", len(got), keepVersions+1, keepVersions)
	}
}

func TestPrune_EmptyOrSingleVersionIsNoop(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs", "example")

	// No versions directory at all yet.
	if err := Prune(dir); err != nil {
		t.Fatalf("Prune on a directory with no versions/ at all: %v", err)
	}

	if err := Write(dir, []byte("key"), []byte("leaf"), []byte("issuer")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := Prune(dir); err != nil {
		t.Fatalf("Prune with a single version: %v", err)
	}
	got := listVersions(t, dir)
	if len(got) != 1 {
		t.Errorf("got %d versions after pruning a single-version directory, want 1 (untouched)", len(got))
	}
}
