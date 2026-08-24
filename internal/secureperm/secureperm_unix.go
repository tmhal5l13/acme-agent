//go:build !windows

// Package secureperm restricts a file or directory to the current user
// (and, on Windows, SYSTEM) - the platform-specific complement to the
// os.Chmod/os.MkdirAll restrictive mode bits this codebase already sets at
// every path that holds a private key, an ACME account, or the SQLite
// database. On Unix, those mode bits (combined with internal/umask's
// process-wide umask) already do the real work, so Protect is a no-op here.
package secureperm

// Protect is a no-op on Unix - os.Chmod at the call site already set the
// restrictive mode that matters on this platform.
func Protect(path string) error { return nil }
