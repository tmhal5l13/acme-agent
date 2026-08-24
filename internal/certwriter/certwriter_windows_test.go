//go:build windows

// These tests assert on "current" being an NTFS junction, not a symlink -
// see certwriter_test.go for the Unix symlink/permission-bit equivalents.
package certwriter

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func readCurrentTest(t *testing.T, dir, name string) []byte {
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

	if got := readCurrentTest(t, dir, "privkey.pem"); !bytes.Equal(got, privKey) {
		t.Errorf("privkey.pem: got %q, want %q", got, privKey)
	}
	if got := readCurrentTest(t, dir, "cert.pem"); !bytes.Equal(got, leaf) {
		t.Errorf("cert.pem: got %q, want %q", got, leaf)
	}
	wantFullchain := append(append([]byte{}, leaf...), issuer...)
	if got := readCurrentTest(t, dir, "fullchain.pem"); !bytes.Equal(got, wantFullchain) {
		t.Errorf("fullchain.pem: got %q, want %q (leaf + issuer concatenated)", got, wantFullchain)
	}
}

// TestWrite_CurrentIsAJunction is the Windows counterpart of the Unix
// symlink test - proving "current" is a reparse point Write retargets in
// place (see swapCurrent), not a directory whose contents get overwritten,
// which would reintroduce the exact bundle-inconsistency window this
// package exists to avoid. Also round-trips buildMountPointBuffer's own
// encoding through windows.Readlink, an independent decoder - if the
// encoder had a byte-layout bug, this is the test most likely to catch it.
func TestWrite_CurrentIsAJunction(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs", "example")
	if err := Write(dir, []byte("key"), []byte("leaf"), []byte("issuer")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	currentPath := filepath.Join(dir, "current")

	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(currentPath))
	if err != nil {
		t.Fatalf("GetFileAttributes: %v", err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		t.Fatal("current does not have the reparse point attribute set")
	}

	version, err := readCurrentVersion(dir)
	if err != nil {
		t.Fatalf("readCurrentVersion: %v", err)
	}
	if version == "" {
		t.Fatal("readCurrentVersion returned an empty version name")
	}
	if filepath.Dir(filepath.Join(dir, "versions", version)) != filepath.Join(dir, "versions") {
		t.Errorf("resolved version %q doesn't live under dir/versions", version)
	}
	if _, err := os.Stat(filepath.Join(dir, "versions", version, "privkey.pem")); err != nil {
		t.Errorf("resolved version directory doesn't contain privkey.pem: %v", err)
	}
}

// TestWrite_RenewalSwapsCompletely proves a second Write (a renewal) fully
// replaces what "current" resolves to - no leftover file from the previous
// version is readable through the new current path - while leaving the
// previous version's own directory untouched, matching the documented
// no-pruning behavior. Unlike the Unix version of this test, it compares
// resolved version names rather than raw symlink target strings, since a
// junction's target is an absolute path, not a relative one.
func TestWrite_RenewalSwapsCompletely(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs", "example")

	if err := Write(dir, []byte("key-v1"), []byte("leaf-v1"), []byte("issuer-v1")); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	firstVersion, err := readCurrentVersion(dir)
	if err != nil {
		t.Fatalf("readCurrentVersion after first write: %v", err)
	}

	if err := Write(dir, []byte("key-v2"), []byte("leaf-v2"), []byte("issuer-v2")); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	secondVersion, err := readCurrentVersion(dir)
	if err != nil {
		t.Fatalf("readCurrentVersion after second write: %v", err)
	}

	if firstVersion == secondVersion {
		t.Fatal("current still resolves to the first version after a second Write — versions aren't actually distinct")
	}

	if got := readCurrentTest(t, dir, "privkey.pem"); string(got) != "key-v2" {
		t.Errorf("current/privkey.pem = %q after renewal, want the new version's content", got)
	}

	// The old version's own files must still exist untouched - Write never
	// deletes prior versions (see the package doc comment on pruning).
	oldPrivKey, err := os.ReadFile(filepath.Join(dir, "versions", firstVersion, "privkey.pem"))
	if err != nil {
		t.Fatalf("read old version's privkey.pem: %v", err)
	}
	if string(oldPrivKey) != "key-v1" {
		t.Errorf("old version's privkey.pem = %q, want unchanged %q", oldPrivKey, "key-v1")
	}
}

// TestSwapCurrent_SecondCallReplacesReparsePointCleanly proves the
// clear-then-set sequence in setJunctionTarget works not just on a
// brand-new "current" directory (which has no reparse point at all) but
// also when retargeting one that's already a junction - the FSCTL_DELETE_REPARSE_POINT
// step this test is actually exercising.
func TestSwapCurrent_SecondCallReplacesReparsePointCleanly(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "versions", "v1"), 0o750); err != nil {
		t.Fatalf("mkdir v1: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "versions", "v2"), 0o750); err != nil {
		t.Fatalf("mkdir v2: %v", err)
	}

	if err := swapCurrent(dir, "v1"); err != nil {
		t.Fatalf("first swapCurrent: %v", err)
	}
	if got, err := readCurrentVersion(dir); err != nil || got != "v1" {
		t.Fatalf("after first swap: got (%q, %v), want (\"v1\", nil)", got, err)
	}

	if err := swapCurrent(dir, "v2"); err != nil {
		t.Fatalf("second swapCurrent: %v", err)
	}
	if got, err := readCurrentVersion(dir); err != nil || got != "v2" {
		t.Fatalf("after second swap: got (%q, %v), want (\"v2\", nil)", got, err)
	}
}
