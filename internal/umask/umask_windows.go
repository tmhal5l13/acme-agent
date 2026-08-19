//go:build windows

package umask

// restrict is a no-op on Windows: there is no process umask concept there
// at all — syscall.Umask isn't defined for windows/*, and file access on
// Windows is governed by ACLs inherited from the parent directory, not a
// permission-bits-minus-umask model. The os.MkdirAll/os.WriteFile mode
// bits used throughout this codebase are also largely ineffective on
// Windows (the os.FileMode passed there only ever toggles the read-only
// attribute on this platform, nothing group/other-access equivalent).
//
// This project does not currently set restrictive Windows ACLs on the
// files/directories it creates (TLS keys, the SQLite database) — a real,
// known gap for a Windows deployment, not something this no-op silently
// papers over. It exists so a Windows build compiles and runs at all
// rather than failing outright on an undefined syscall.
func restrict() {}
