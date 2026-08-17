package certwriter

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func readCurrent(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "current", name))
	if err != nil {
		t.Fatalf("read current/%s: %v", name, err)
	}
	return data
}

func TestWrite_FilesLandUnderCurrent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs", "example")
	privKey, leaf, issuer := []byte("PRIVATE KEY"), []byte("LEAF CERT"), []byte("ISSUER CERT")

	if err := Write(dir, privKey, leaf, issuer); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if got := readCurrent(t, dir, "privkey.pem"); !bytes.Equal(got, privKey) {
		t.Errorf("privkey.pem: got %q, want %q", got, privKey)
	}
	if got := readCurrent(t, dir, "cert.pem"); !bytes.Equal(got, leaf) {
		t.Errorf("cert.pem: got %q, want %q", got, leaf)
	}
	wantFullchain := append(append([]byte{}, leaf...), issuer...)
	if got := readCurrent(t, dir, "fullchain.pem"); !bytes.Equal(got, wantFullchain) {
		t.Errorf("fullchain.pem: got %q, want %q (leaf + issuer concatenated)", got, wantFullchain)
	}
}

// TestWrite_CurrentIsASymlink is the actual point of this package's
// design: "current" must be a symlink Write repoints atomically, not a
// directory whose contents get overwritten in place — the latter would
// reintroduce the exact bundle-inconsistency window this package exists
// to avoid.
func TestWrite_CurrentIsASymlink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs", "example")
	if err := Write(dir, []byte("key"), []byte("leaf"), []byte("issuer")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	info, err := os.Lstat(filepath.Join(dir, "current"))
	if err != nil {
		t.Fatalf("lstat current: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("current is not a symlink")
	}

	target, err := os.Readlink(filepath.Join(dir, "current"))
	if err != nil {
		t.Fatalf("readlink current: %v", err)
	}
	if filepath.Dir(target) != "versions" {
		t.Errorf("current points to %q, want something under versions/", target)
	}
}

// TestWrite_RenewalSwapsCompletely proves a second Write (a renewal) fully
// replaces what "current" resolves to — no leftover file from the
// previous version is readable through the new current path — while
// leaving the previous version's own directory untouched, matching the
// documented no-pruning behavior.
func TestWrite_RenewalSwapsCompletely(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs", "example")

	if err := Write(dir, []byte("key-v1"), []byte("leaf-v1"), []byte("issuer-v1")); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	firstTarget, err := os.Readlink(filepath.Join(dir, "current"))
	if err != nil {
		t.Fatalf("readlink after first write: %v", err)
	}

	if err := Write(dir, []byte("key-v2"), []byte("leaf-v2"), []byte("issuer-v2")); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	secondTarget, err := os.Readlink(filepath.Join(dir, "current"))
	if err != nil {
		t.Fatalf("readlink after second write: %v", err)
	}

	if firstTarget == secondTarget {
		t.Fatal("current still points at the first version after a second Write — versions aren't actually distinct")
	}

	if got := readCurrent(t, dir, "privkey.pem"); string(got) != "key-v2" {
		t.Errorf("current/privkey.pem = %q after renewal, want the new version's content", got)
	}

	// The old version's own files must still exist untouched - Write never
	// deletes prior versions (see the package doc comment on pruning).
	oldPrivKey, err := os.ReadFile(filepath.Join(dir, firstTarget, "privkey.pem"))
	if err != nil {
		t.Fatalf("read old version's privkey.pem: %v", err)
	}
	if string(oldPrivKey) != "key-v1" {
		t.Errorf("old version's privkey.pem = %q, want unchanged %q", oldPrivKey, "key-v1")
	}
}

func TestWrite_Permissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs", "example")
	if err := Write(dir, []byte("key"), []byte("leaf"), []byte("issuer")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	cases := []struct {
		path string
		want os.FileMode
	}{
		{"current/privkey.pem", 0o600},
		{"current/cert.pem", 0o644},
		{"current/fullchain.pem", 0o644},
	}
	for _, c := range cases {
		info, err := os.Stat(filepath.Join(dir, c.path))
		if err != nil {
			t.Fatalf("stat %s: %v", c.path, err)
		}
		if got := info.Mode().Perm(); got != c.want {
			t.Errorf("%s: got perm %o, want %o", c.path, got, c.want)
		}
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o750 {
		t.Errorf("dir perm: got %o, want %o", got, 0o750)
	}
}
