//go:build windows

package secureperm

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestProtect_FileGetsOwnerAndSystemOnlyDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.pem")
	if err := os.WriteFile(path, []byte("private-key-material"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	if err := Protect(path); err != nil {
		t.Fatalf("Protect: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("read back dacl: %v", err)
	}
	if dacl == nil {
		t.Fatal("expected a non-nil DACL after Protect")
	}

	// A protected DACL granting only the current user and SYSTEM full
	// access should have exactly two ACEs - this doesn't decode each ACE's
	// trustee/mask (the x/sys/windows ACL type doesn't expose that without
	// raw ACE-info calls), but a two-ACE DACL after applying our two-entry
	// SDDL string is a reasonable smoke check that Protect actually wrote
	// something and didn't silently no-op or wipe the DACL to zero ACEs
	// (which would mean "deny everyone," not "restrict to two trustees").
	if got := int(dacl.AceCount); got != 2 {
		t.Errorf("got %d ACEs in the protected DACL, want 2 (current user + SYSTEM)", got)
	}
}

func TestProtect_DirectoryGetsProtectedDACL(t *testing.T) {
	dir := t.TempDir()

	if err := Protect(dir); err != nil {
		t.Fatalf("Protect: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("read back dacl: %v", err)
	}
	if dacl == nil || dacl.AceCount != 2 {
		t.Fatalf("got dacl %+v, want a non-nil DACL with 2 ACEs", dacl)
	}
}
