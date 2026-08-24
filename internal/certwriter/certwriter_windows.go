//go:build windows

package certwriter

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// swapCurrent atomically repoints dir/current at dir/versions/versionName
// using an NTFS junction (a mount-point reparse point) instead of a
// symlink: creating a symlink requires SeCreateSymbolicLinkPrivilege
// (admin, or Developer Mode enabled), which a non-elevated spoke service
// wouldn't have. Junctions don't require that privilege - the same reason
// tools like npm and Docker Desktop use junctions rather than symlinks for
// privilege-free directory links on Windows.
//
// Unlike a symlink, a junction can't be swapped by renaming it into place
// - Windows doesn't support atomically replacing one directory with
// another via rename the way a symlink (a small, non-directory object) can
// be. Instead, dir/current is created once, on the first call, as a plain
// directory that is never removed thereafter; every subsequent call
// retargets its reparse point in place: clear whatever reparse data it
// currently holds, then write the new target. Both operate on the same
// persistent directory object rather than replacing it - as close to the
// symlink-rename guarantee as Windows permits. A crash between the two
// leaves current as a plain, empty directory (no reparse point at all),
// not a torn mix of old and new files - a safe, detectable failure mode
// for a caller expecting to find a complete bundle there.
func swapCurrent(dir, versionName string) error {
	currentPath := filepath.Join(dir, "current")
	if err := os.MkdirAll(currentPath, 0o750); err != nil {
		return fmt.Errorf("create current directory: %w", err)
	}

	target, err := filepath.Abs(filepath.Join(dir, "versions", versionName))
	if err != nil {
		return fmt.Errorf("resolve absolute version path: %w", err)
	}

	if err := setJunctionTarget(currentPath, target); err != nil {
		return fmt.Errorf("retarget current junction: %w", err)
	}
	return nil
}

// setJunctionTarget makes link (an existing, empty-or-already-a-junction
// directory) a junction pointing at target.
func setJunctionTarget(link, target string) error {
	linkPtr, err := windows.UTF16PtrFromString(link)
	if err != nil {
		return fmt.Errorf("encode path: %w", err)
	}
	h, err := windows.CreateFile(linkPtr, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", link, err)
	}
	defer windows.CloseHandle(h)

	// FSCTL_SET_REPARSE_POINT fails on a path that already has reparse
	// data - clear it first. A brand-new "current" directory has none, so
	// this is expected to (harmlessly) fail on the very first call for a
	// given dir; the error is deliberately ignored rather than checked
	// against a specific code, since "there was nothing to delete" and
	// "there was something and it's now gone" both leave us in the same
	// state we need for the FSCTL_SET_REPARSE_POINT call that follows.
	var bytesReturned uint32
	deleteBuf := buildDeleteReparsePointBuffer()
	_ = windows.DeviceIoControl(h, windows.FSCTL_DELETE_REPARSE_POINT,
		&deleteBuf[0], uint32(len(deleteBuf)), nil, 0, &bytesReturned, nil)

	setBuf, err := buildMountPointBuffer(target)
	if err != nil {
		return err
	}
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT,
		&setBuf[0], uint32(len(setBuf)), nil, 0, &bytesReturned, nil); err != nil {
		return fmt.Errorf("set reparse point: %w", err)
	}
	return nil
}

// buildDeleteReparsePointBuffer builds the DeviceIoControl input buffer for
// FSCTL_DELETE_REPARSE_POINT: just the 8-byte REPARSE_DATA_BUFFER header
// (ReparseTag + a zero ReparseDataLength + Reserved), no path data - per
// FSCTL_DELETE_REPARSE_POINT's documented contract, which only inspects
// the tag to confirm it matches what's actually present.
func buildDeleteReparsePointBuffer() []byte {
	buf := make([]byte, 0, 8)
	buf = binary.LittleEndian.AppendUint32(buf, windows.IO_REPARSE_TAG_MOUNT_POINT)
	buf = binary.LittleEndian.AppendUint16(buf, 0) // ReparseDataLength
	buf = binary.LittleEndian.AppendUint16(buf, 0) // Reserved
	return buf
}

// buildMountPointBuffer builds the complete DeviceIoControl input buffer
// for FSCTL_SET_REPARSE_POINT, targeting target as an NTFS junction:
//
//	REPARSE_DATA_BUFFER {
//	    ULONG  ReparseTag;              // IO_REPARSE_TAG_MOUNT_POINT
//	    USHORT ReparseDataLength;       // bytes from SubstituteNameOffset onward
//	    USHORT Reserved;
//	    struct {                        // MountPointReparseBuffer
//	        USHORT SubstituteNameOffset;
//	        USHORT SubstituteNameLength;
//	        USHORT PrintNameOffset;
//	        USHORT PrintNameLength;
//	        WCHAR  PathBuffer[];         // SubstituteName then PrintName, UTF-16
//	    };
//	}
//
// golang.org/x/sys/windows declares this layout only as unexported types
// (used internally by its own Readlink), so it's reproduced here rather
// than imported. Layout and field values (the "\??\" NT-namespace prefix
// on SubstituteName, no prefix on PrintName, offsets/lengths in bytes
// excluding each string's NUL terminator) match Go's own standard library
// coverage of this exact mechanism (os package's directory-junction tests
// build and verify a junction the same way), not just the header docs.
func buildMountPointBuffer(target string) ([]byte, error) {
	substitute, err := windows.UTF16FromString(`\??\` + target)
	if err != nil {
		return nil, fmt.Errorf("encode substitute name: %w", err)
	}
	print, err := windows.UTF16FromString(target)
	if err != nil {
		return nil, fmt.Errorf("encode print name: %w", err)
	}

	pathBuf := make([]byte, 0, (len(substitute)+len(print))*2)
	for _, u := range substitute {
		pathBuf = binary.LittleEndian.AppendUint16(pathBuf, u)
	}
	for _, u := range print {
		pathBuf = binary.LittleEndian.AppendUint16(pathBuf, u)
	}

	// Lengths exclude each string's own NUL terminator (per
	// SubstituteNameLength/PrintNameLength's documented meaning), but the
	// NUL character itself stays in pathBuf - printNameOffset therefore
	// starts right after substitute's NUL, not right after subLen.
	subLen := uint16(len(substitute)-1) * 2
	printLen := uint16(len(print)-1) * 2
	subOffset := uint16(0)
	printOffset := uint16(len(substitute)) * 2

	const mountBufHeaderSize = 8 // SubstituteNameOffset/Length + PrintNameOffset/Length, 4 uint16 fields
	reparseDataLength := uint16(mountBufHeaderSize) + uint16(len(pathBuf))

	buf := make([]byte, 0, 8+int(reparseDataLength))
	buf = binary.LittleEndian.AppendUint32(buf, windows.IO_REPARSE_TAG_MOUNT_POINT)
	buf = binary.LittleEndian.AppendUint16(buf, reparseDataLength)
	buf = binary.LittleEndian.AppendUint16(buf, 0) // Reserved
	buf = binary.LittleEndian.AppendUint16(buf, subOffset)
	buf = binary.LittleEndian.AppendUint16(buf, subLen)
	buf = binary.LittleEndian.AppendUint16(buf, printOffset)
	buf = binary.LittleEndian.AppendUint16(buf, printLen)
	buf = append(buf, pathBuf...)
	return buf, nil
}

// readCurrentVersion returns the version-directory name dir/current's
// junction currently targets, or "" if dir/current doesn't exist yet -
// used by Prune to know which version must never be deleted. Uses
// golang.org/x/sys/windows's own Readlink, which already handles
// IO_REPARSE_TAG_MOUNT_POINT (not just IO_REPARSE_TAG_SYMLINK) - no need
// to hand-roll the read side the way buildMountPointBuffer hand-rolls the
// write side, since x/sys exports this one already.
func readCurrentVersion(dir string) (string, error) {
	buf := make([]byte, 4096)
	n, err := windows.Readlink(filepath.Join(dir, "current"), buf)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return filepath.Base(string(buf[:n])), nil
}

// fsyncDir is a no-op on Windows. The Unix implementation exists because
// several POSIX filesystems (ext4 among them) don't guarantee a directory
// entry (a file creation, rename, or removal within it) is durable across
// a crash without an explicit fsync of the directory itself, separate from
// fsyncing the file. NTFS doesn't have this gap: directory metadata
// updates go through its own transactional log as a normal part of every
// operation, with no equivalent userspace call needed (and, in practice,
// none reliably available - os.Open's directory handle lacks the write
// access FlushFileBuffers requires, confirmed by this exact call failing
// with "Access is denied" against a real windows-latest CI run before
// this function existed). This isn't a gap being silently accepted the
// way internal/umask's Windows no-op is - it reflects a real difference
// in what each filesystem already guarantees on its own.
func fsyncDir(dir string) error { return nil }
