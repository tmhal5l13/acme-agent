// Package umask restricts the process's default file-creation permissions
// on platforms that have the concept, so files this project creates (TLS
// keys, the SQLite database, etc.) default to owner-only access even
// before any explicit os.Chmod call — belt-and-suspenders alongside the
// explicit permission bits already passed to os.MkdirAll/os.WriteFile
// throughout the codebase.
package umask

// Restrict sets a restrictive process umask (0077: no group/other access)
// on platforms where umask is a real concept. See umask_windows.go for why
// this is a deliberate no-op on Windows rather than an equivalent.
func Restrict() {
	restrict()
}
