//go:build !windows

package umask

import "syscall"

func restrict() {
	syscall.Umask(0o077)
}
