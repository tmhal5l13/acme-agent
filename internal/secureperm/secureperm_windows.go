//go:build windows

// Package secureperm restricts a file or directory to the current user
// (and, on Windows, SYSTEM) - the platform-specific complement to the
// os.Chmod/os.MkdirAll restrictive mode bits this codebase already sets at
// every path that holds a private key, an ACME account, or the SQLite
// database. Windows has no umask and its os.FileMode bits only ever toggle
// the read-only attribute (see internal/umask's doc comment) - real access
// control there is a DACL, which this file sets explicitly.
package secureperm

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// Protect replaces path's DACL with one granting full access only to the
// current process's user and to SYSTEM (a Windows service commonly runs as
// SYSTEM), discarding whatever broader access it inherited from its parent
// directory. Call it right after creating anything that holds a private
// key, a bearer token, or the SQLite database - the same set of paths this
// codebase already os.Chmod's restrictively on Unix.
func Protect(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("secureperm: resolve current user sid: %w", err)
	}

	// D: starts a DACL. "P" marks it protected, so the ACEs below fully
	// replace whatever the object would otherwise inherit from its parent
	// rather than being merged with it. Each (A;;FA;;;<sid>) grants (A)
	// full access (FA) to one trustee - the resolved SID string for the
	// current user, and "SY" (the well-known LocalSystem alias) alongside
	// it.
	sddl := fmt.Sprintf("D:P(A;;FA;;;%s)(A;;FA;;;SY)", sid)

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("secureperm: build security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("secureperm: extract dacl: %w", err)
	}

	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("secureperm: set security info on %s: %w", path, err)
	}
	return nil
}

// currentUserSID returns the string form (e.g. "S-1-5-21-...") of the
// current process token's user SID.
func currentUserSID() (string, error) {
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("get token user: %w", err)
	}
	return user.User.Sid.String(), nil
}
