//go:build !windows

// Package winservice integrates the spoke process with the Windows
// Service Control Manager (SCM) when it's running as a registered Windows
// service - a no-op everywhere else, so callers (cmd/acme-spoke/main.go)
// can call RunIfService unconditionally without their own build tags.
package winservice

// RunIfService is a no-op on Unix - there is no Windows SCM to integrate
// with, and this platform's process supervision (systemd) already talks
// to the process via the signals stop's caller already listens for.
func RunIfService(stop func(), done <-chan struct{}) error { return nil }
