// Package certwriter writes issued certificate material to disk atomically
// and with restrictive permissions.
package certwriter

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Write atomically installs a certificate bundle (private key, leaf
// certificate, and full chain) under dir, such that any reader ever sees
// either the complete previous bundle or the complete new one — never a
// mix of old and new files. dir is created if necessary.
//
// This matters because the three files aren't independent: privkey.pem
// only means something paired with the cert.pem it was issued alongside.
// Writing three separate files in sequence — even with each individual
// write itself atomic — leaves a real window where a crash between file N
// and file N+1 strands a new key next to an old, non-matching
// certificate. Fixed with the standard pattern for atomically swapping a
// whole directory's worth of files: write the complete new bundle into
// its own versioned directory, then atomically repoint a "current"
// symlink at it. Renaming a symlink is a single atomic operation on the
// same filesystem, exactly like the per-file rename this package already
// relied on before — this just applies that same guarantee to the bundle
// as a whole instead of to each file individually.
//
// Callers (reload hooks, the actual consuming service) should read from
// dir/current/{privkey.pem,cert.pem,fullchain.pem} — never from dir
// directly, which no longer holds the files itself.
//
// Previous versions under dir/versions/ are not cleaned up by this
// function; they accumulate across renewals. At roughly one renewal every
// 60-90 days this isn't a practical problem on any realistic deployment
// timeline, but an operator wanting to reclaim the space (or wanting a
// bounded rollback history instead of an unbounded one) would need to
// prune dir/versions/ themselves.
func Write(dir string, privateKeyPEM, leafCertPEM, issuerCertPEM []byte) error {
	// os.MkdirAll's mode argument is subject to the process umask just like
	// file creation, so a restrictive umask (as main.go sets) silently turns
	// the requested 0750 into 0700 — locking out the group read+traverse
	// access a reload target (e.g. nginx running as its own user, in this
	// group) needs to reach the installed files. Chmod explicitly for every
	// directory level MkdirAll may have created, since explicit Chmod is not
	// subject to umask.
	parent := filepath.Dir(dir)
	versionsDir := filepath.Join(dir, "versions")
	suffix, err := randomHex(4)
	if err != nil {
		return fmt.Errorf("generate version suffix: %w", err)
	}
	// The random suffix (not just the timestamp) is what actually
	// guarantees a fresh directory name every call — nanosecond-formatted
	// time alone could theoretically collide under coarse clock
	// resolution, which would silently reuse a prior version's directory
	// instead of creating a genuinely new one.
	versionName := time.Now().UTC().Format("20060102T150405") + "-" + suffix
	versionDir := filepath.Join(versionsDir, versionName)
	for _, d := range []string{parent, dir, versionsDir, versionDir} {
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
		if err := writeAtomic(filepath.Join(versionDir, w.name), w.data, w.perm); err != nil {
			return err
		}
	}

	// The three files above are now durably on disk — writeAtomic fsyncs
	// each one before renaming it into place — but the directory entries
	// recording their names still need their own fsync to be durable: a
	// file's fsync only guarantees that file's data, not that the
	// directory pointing to it survives a crash. Same reasoning applies to
	// dir itself after the symlink swap below.
	if err := fsyncDir(versionDir); err != nil {
		return err
	}

	// Atomically point "current" at the new version. Renaming a symlink is
	// the same single-syscall atomic replace this package already relies
	// on for individual files — nothing ever observes a symlink that's
	// half-old, half-new, the way the three plain files above could have
	// been observed mid-swap under the previous, non-versioned layout.
	currentPath := filepath.Join(dir, "current")
	tmpSymlink := currentPath + ".tmp"
	_ = os.Remove(tmpSymlink) // clean up a leftover from a prior crash, if any
	relTarget := filepath.Join("versions", versionName)
	if err := os.Symlink(relTarget, tmpSymlink); err != nil {
		return fmt.Errorf("create current symlink: %w", err)
	}
	if err := os.Rename(tmpSymlink, currentPath); err != nil {
		return fmt.Errorf("swap current symlink: %w", err)
	}

	if err := fsyncDir(dir); err != nil {
		return err
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

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// fsyncDir fsyncs a directory's own metadata (which names point to which
// inodes) rather than any file's contents — required on POSIX for a file
// creation, rename, or removal within it to be durable across a crash,
// distinct from and in addition to fsyncing the file itself.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s for fsync: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", dir, err)
	}
	return nil
}
