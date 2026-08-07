// Package certwriter writes issued certificate material to disk atomically
// and with restrictive permissions.
package certwriter

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write atomically writes a certificate bundle to
// <dir>/{privkey.pem, cert.pem, fullchain.pem}. dir is created if necessary.
//
// Each file is written to a ".tmp" sibling, fsynced, then renamed into
// place — rename is atomic on the same filesystem, so a concurrently
// running reload hook (or nginx re-reading the file) never observes a
// half-written cert or key.
func Write(dir string, privateKeyPEM, leafCertPEM, issuerCertPEM []byte) error {
	// os.MkdirAll's mode argument is subject to the process umask just like
	// file creation, so a restrictive umask (as main.go sets) silently turns
	// the requested 0750 into 0700 — locking out the group read+traverse
	// access a reload target (e.g. nginx running as its own user, in this
	// group) needs to reach cert.pem/fullchain.pem. Chmod explicitly for
	// both this directory and its "certs" parent, since MkdirAll may have
	// created either or both of them, and explicit Chmod is not subject to
	// umask.
	parent := filepath.Dir(dir)
	for _, d := range []string{parent, dir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
		if err := os.Chmod(d, 0o750); err != nil {
			return fmt.Errorf("chmod %s: %w", d, err)
		}
	}

	fullchain := append(append([]byte{}, leafCertPEM...), issuerCertPEM...)

	writes := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{"privkey.pem", privateKeyPEM, 0o600},
		{"cert.pem", leafCertPEM, 0o644},
		{"fullchain.pem", fullchain, 0o644},
	}

	for _, w := range writes {
		if err := writeAtomic(filepath.Join(dir, w.name), w.data, w.perm); err != nil {
			return err
		}
	}
	return nil
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	defer os.Remove(tmp) // no-op once the rename below succeeds

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	// OpenFile's perm argument is subject to umask, so set it explicitly.
	if err := os.Chmod(tmp, perm); err != nil {
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmp, path, err)
	}
	return nil
}
