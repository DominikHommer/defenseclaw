// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package workspace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// Linux UAPI include/uapi/linux/openat2.h: RESOLVE_CACHED (since 5.12).
// The pinned x/sys version does not export this already reviewed flag.
const linuxHostResolveCached = 0x20
const linuxHostResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV | linuxHostResolveCached

type linuxHostIdentity struct {
	dev, ino, mount uint64
	mode, uid       uint32
	links           uint64
	size            int64
	modified        unix.Timespec
	changed         unix.Timespec
}

func (id linuxHostIdentity) sameObject(other linuxHostIdentity) bool {
	return id.dev == other.dev && id.ino == other.ino && id.mount == other.mount && id.mode&unix.S_IFMT == other.mode&unix.S_IFMT
}

func (id linuxHostIdentity) label() string {
	return fmt.Sprintf("linux:%x:%x:%x", id.dev, id.ino, id.mount)
}

// These helpers inspect only held descriptors. Mount crossing is independently
// refused at every source open; a later native factory must still verify its
// own source mount/no-IDMAP/topology contract before namespace creation.
func linuxHostInfo(file *os.File, private bool) (linuxHostIdentity, error) {
	var stat unix.Stat_t
	var mount unix.Statx_t
	var filesystem unix.Statfs_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return linuxHostIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG && stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Size < 0 ||
		stat.Nlink == 0 || stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink != 1 {
		return linuxHostIdentity{}, errors.New("workspace: Linux host staging requires directories and single-link regular files")
	}
	if private && (stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o077 != 0) {
		return linuxHostIdentity{}, errors.New("workspace: Linux staging objects must already be current-user private")
	}
	if err := unix.Fstatfs(int(file.Fd()), &filesystem); err != nil {
		return linuxHostIdentity{}, err
	}
	switch filesystem.Type {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC:
	default:
		return linuxHostIdentity{}, errors.New("workspace: Linux host staging requires its admitted local filesystem floor")
	}
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &mount); err != nil {
		return linuxHostIdentity{}, err
	}
	if mount.Mask&unix.STATX_MNT_ID == 0 || mount.Mnt_id == 0 {
		return linuxHostIdentity{}, errors.New("workspace: Linux held mount identity is unavailable")
	}
	return linuxHostIdentity{dev: stat.Dev, ino: stat.Ino, mount: mount.Mnt_id, mode: stat.Mode, uid: stat.Uid,
		links: uint64(stat.Nlink), size: stat.Size, modified: stat.Mtim, changed: stat.Ctim}, nil
}

type linuxHostAccess struct {
	root, proc *os.File
	// Failed validation must not lose an allocated alias; uncertain native
	// close is sticky and retains exact objects rather than retrying FD values.
	retainedFiles []*os.File
	retainedRoots []*os.Root
	closeErr      error
}

func (a *linuxHostAccess) closeFile(file *os.File) error {
	if err := file.Close(); err != nil {
		a.retainedFiles = append(a.retainedFiles, file)
		a.closeErr = errors.Join(a.closeErr, err)
		return err
	}
	return nil
}

func (a *linuxHostAccess) closeRetained() error {
	if a.closeErr != nil {
		return a.closeErr
	}
	for i, root := range a.retainedRoots {
		if root != nil {
			if err := root.Close(); err != nil {
				a.closeErr = err
				return err
			}
			a.retainedRoots[i] = nil
		}
	}
	return nil
}

func (a *linuxHostAccess) refused(cause error) (*linuxHostAccess, error) {
	if err := a.close(); err != nil {
		return a, errors.Join(cause, err)
	}
	return nil, cause
}

func newLinuxHostAccess() (*linuxHostAccess, error) {
	if os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return nil, errors.New("workspace: Linux host staging refuses changed process credentials")
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	access := &linuxHostAccess{root: os.NewFile(uintptr(fd), "host-staging-root")}
	if _, err := linuxHostInfo(access.root, false); err != nil {
		return access.refused(err)
	}
	// This is the one intentional capability-alias facility, not an input
	// pathname resolver. A stale proc PID view or non-proc replacement refuses.
	var pid [12]byte
	n, err := unix.Readlink("/proc/self", pid[:])
	if err != nil || n >= len(pid) || string(pid[:n]) != strconv.Itoa(os.Getpid()) {
		return access.refused(errors.Join(errors.New("workspace: Linux host staging requires matching procfs PID view"), err))
	}
	fd, err = unix.Open("/proc/self/fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return access.refused(err)
	}
	access.proc = os.NewFile(uintptr(fd), "host-staging-proc-fds")
	var stat unix.Statfs_t
	if err := unix.Fstatfs(fd, &stat); err != nil || stat.Type != unix.PROC_SUPER_MAGIC {
		return access.refused(errors.Join(errors.New("workspace: Linux descriptor aliases require procfs"), err))
	}
	return access, nil
}

func (a *linuxHostAccess) close() error {
	if err := a.closeRetained(); err != nil {
		return err
	}
	for _, file := range []**os.File{&a.proc, &a.root} {
		if *file != nil {
			if err := (*file).Close(); err != nil {
				a.closeErr = err
				return err
			}
			*file = nil
		}
	}
	return nil
}

func linuxHostAbsolute(name string) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || name == "/" || len(name) > capturedPathMaxBytes || !utf8.ValidString(name) {
		return errors.New("workspace: Linux host path must be a clean bounded absolute path")
	}
	for _, char := range name {
		if unicode.IsControl(char) || char == utf8.RuneError {
			return errors.New("workspace: Linux host path contains unsupported characters")
		}
	}
	return nil
}

func linuxHostOpen(parent *os.File, name string, directory bool) (*os.File, error) {
	flags := unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{Flags: uint64(flags), Resolve: linuxHostResolve})
	if err != nil {
		return nil, err // including EAGAIN: no uncached or pathname fallback
	}
	return os.NewFile(uintptr(fd), "host-staging-object"), nil
}

func (a *linuxHostAccess) absolute(name string) (*os.File, error) {
	if err := linuxHostAbsolute(name); err != nil {
		return nil, err
	}
	return linuxHostOpen(a.root, strings.TrimPrefix(name, "/"), true)
}

// Convert an O_PATH pin only after proving regular-file/directory type. Opening
// the original entry directly could trigger a substituted device before fstat.
// The numeric name selects a still-held descriptor, never a caller pathname.
func (a *linuxHostAccess) readable(pin *os.File, private bool) (*os.File, error) {
	before, err := linuxHostInfo(pin, private)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(a.proc.Fd()), strconv.FormatUint(uint64(pin.Fd()), 10), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "host-staging-readable")
	after, err := linuxHostInfo(file, private)
	if err != nil || !before.sameObject(after) || before != after {
		return nil, errors.Join(errors.New("workspace: held Linux read object changed"), err, a.closeFile(file))
	}
	return file, nil
}

func (a *linuxHostAccess) heldRoot(pin *os.File, private bool) (*os.Root, error) {
	before, err := linuxHostInfo(pin, private)
	if err != nil || before.mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.Join(errors.New("workspace: Linux root capability is not a directory"), err)
	}
	// os.Root has no descriptor constructor. Only this exact held numeric
	// capability alias is used; TreePath and original display paths are not.
	root, err := os.OpenRoot("/proc/self/fd/" + strconv.FormatUint(uint64(pin.Fd()), 10))
	if err != nil {
		return nil, err
	}
	check, err := root.Open(".")
	if err != nil {
		a.retainedRoots = append(a.retainedRoots, root)
		return nil, err
	}
	after, infoErr := linuxHostInfo(check, private)
	flags, flagErr := unix.FcntlInt(check.Fd(), unix.F_GETFD, 0)
	closeErr := a.closeFile(check)
	last, lastErr := linuxHostInfo(pin, private)
	if infoErr != nil || flagErr != nil || closeErr != nil || lastErr != nil || flags&unix.FD_CLOEXEC == 0 || before != after || before != last {
		a.retainedRoots = append(a.retainedRoots, root)
		return nil, errors.Join(errors.New("workspace: Linux root capability alias validation failed"), infoErr, flagErr, closeErr, lastErr)
	}
	return root, nil
}

func duplicateLinuxHostRoot(file *os.File, expected linuxHostIdentity) (*os.File, error) {
	before, err := linuxHostInfo(file, true)
	if err != nil || !before.sameObject(expected) {
		return nil, errors.Join(errors.New("workspace: held Linux sanitized root identity changed"), err)
	}
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	copy := os.NewFile(uintptr(fd), "host-stage-root-copy")
	after, infoErr := linuxHostInfo(copy, true)
	flags, flagErr := unix.FcntlInt(copy.Fd(), unix.F_GETFD, 0)
	if infoErr != nil || flagErr != nil || !after.sameObject(before) || flags&unix.FD_CLOEXEC == 0 {
		// Non-nil on error preserves allocated duplicate custody in RootLease.
		return copy, errors.Join(errors.New("workspace: Linux root duplicate validation failed"), infoErr, flagErr)
	}
	return copy, nil
}

func (a *linuxHostAccess) remove(ctx context.Context, parent *os.File, name string, expected linuxHostIdentity, depth int, budget *int) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	*budget--
	if *budget < 0 || depth > hostStageMaxDepth+8 || validateWindowsHostStageName(name) != nil {
		return errors.New("workspace: bounded Linux owned cleanup refused")
	}
	pin, err := linuxHostOpen(parent, name, false)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, a.closeFile(pin)) }()
	id, err := linuxHostInfo(pin, true)
	if err != nil || !id.sameObject(expected) {
		return errors.Join(errors.New("workspace: Linux cleanup target identity changed"), err)
	}
	flags := 0
	if id.mode&unix.S_IFMT == unix.S_IFDIR {
		flags = unix.AT_REMOVEDIR
		directory, err := a.readable(pin, true)
		if err != nil {
			return err
		}
		defer func() { retErr = errors.Join(retErr, a.closeFile(directory)) }()
		for {
			entries, readErr := directory.ReadDir(128)
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return readErr
			}
			for _, entry := range entries {
				child, err := linuxHostOpen(directory, entry.Name(), false)
				if err != nil {
					return err
				}
				childID, statErr := linuxHostInfo(child, true)
				if statErr != nil {
					return errors.Join(statErr, a.closeFile(child))
				}
				// Keep the sampled child alive through recursive removal. Its
				// inode cannot be freed/reused between identity observations.
				removeErr := a.remove(ctx, directory, entry.Name(), childID, depth+1, budget)
				if err := errors.Join(removeErr, a.closeFile(child)); err != nil {
					return err
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
		}
	}
	// unlinkat has no compare-by-handle operation. The retained private parent
	// and pre-unlink identity sample are the stated trusted-producer contract;
	// arbitrary same-UID host mutation is not an immutable-parent guarantee.
	check, err := linuxHostOpen(parent, name, false)
	if err != nil {
		return err
	}
	current, statErr := linuxHostInfo(check, true)
	closeErr := a.closeFile(check)
	if statErr != nil || closeErr != nil || !id.sameObject(current) {
		return errors.Join(errors.New("workspace: Linux owned cleanup name changed"), statErr, closeErr)
	}
	return unix.Unlinkat(int(parent.Fd()), name, flags)
}

// Preserve missing-file semantics without allowing an unreadable config to be
// confused with absence. Every lookup remains beneath the held root mount.
func linuxHostMissing(err error) bool { return errors.Is(err, fs.ErrNotExist) }
