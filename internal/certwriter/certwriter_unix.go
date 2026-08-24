//go:build !windows

package certwriter

import (
	"fmt"
	"os"
	"path/filepath"
)

// swapCurrent atomically repoints dir/current at dir/versions/versionName.
// Renaming a symlink is the same single-syscall atomic replace this
// package already relies on for individual files - nothing ever observes
// a symlink that's half-old, half-new.
func swapCurrent(dir, versionName string) error {
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
	return nil
}

// readCurrentVersion returns the version-directory name (e.g.
// "20260101T000000-abcd1234") that dir/current currently resolves to, or
// "" if dir/current doesn't exist yet - used by Prune to know which
// version must never be deleted.
func readCurrentVersion(dir string) (string, error) {
	target, err := os.Readlink(filepath.Join(dir, "current"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return filepath.Base(target), nil
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
