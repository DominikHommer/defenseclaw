// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package namespaceinit

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

const privateRootImageBudget int64 = 24 << 20
const PrivateRootReady = "DCAX_PRIVATE_ROOT_READY_V1\n"
const PrivateRootGrant = "DCAX_PRIVATE_ROOT_GRANT_V1\n"

// PinnedSealedFile is a trusted caller's already-admitted, sealed input. Its
// digest proves input integrity; it does not grant a provider or policy route.
type PinnedSealedFile struct {
	File   *os.File
	Size   int64
	SHA256 [32]byte
}

type PrivateRootImages struct {
	Peer       PinnedSealedFile
	Bubblewrap PinnedSealedFile
	Payload    PinnedSealedFile
}

type PrivateRootDevices struct {
	Null    *os.File
	Zero    *os.File
	Full    *os.File
	Random  *os.File
	URandom *os.File
	TTY     *os.File
}

// PrivateRootPlan is host-owned. Every handle except the caller's held self
// and workload executable is consumed exactly once by SetupPrivateRoot.
// FD3 is the existing sealed namespace proof; fixed child routing uses FD4/5
// for GRANT/READY, FD8-10 for images and FD11-16 for six character devices.
type PrivateRootPlan struct {
	Grant   *os.File
	Ready   *os.File
	Images  PrivateRootImages
	Devices PrivateRootDevices
}

type privateDevice struct {
	leaf     string
	file     *os.File
	fd       uintptr
	major    uint32
	minor    uint32
	identity unix.Stat_t
}

func privateRootImageRoles(p *PrivateRootPlan) [3]*PinnedSealedFile {
	return [3]*PinnedSealedFile{&p.Images.Peer, &p.Images.Bubblewrap, &p.Images.Payload}
}

func privateRootDeviceRoles(p *PrivateRootPlan) [6]privateDevice {
	return [6]privateDevice{
		{leaf: "null", file: p.Devices.Null, fd: 11, major: 1, minor: 3},
		{leaf: "zero", file: p.Devices.Zero, fd: 12, major: 1, minor: 5},
		{leaf: "full", file: p.Devices.Full, fd: 13, major: 1, minor: 7},
		{leaf: "random", file: p.Devices.Random, fd: 14, major: 1, minor: 8},
		{leaf: "urandom", file: p.Devices.URandom, fd: 15, major: 1, minor: 9},
		{leaf: "tty", file: p.Devices.TTY, fd: 16, major: 5, minor: 0},
	}
}

func closePrivateRootPlan(p *PrivateRootPlan) (resultErr error) {
	if p == nil {
		return nil
	}
	files := []*os.File{p.Grant, p.Ready, p.Images.Peer.File, p.Images.Bubblewrap.File, p.Images.Payload.File,
		p.Devices.Null, p.Devices.Zero, p.Devices.Full, p.Devices.Random, p.Devices.URandom, p.Devices.TTY}
	*p = PrivateRootPlan{}
	seen := make(map[uintptr]bool, len(files))
	for _, file := range files {
		if file == nil {
			continue
		}
		fd := file.Fd()
		if fd == 3 || seen[fd] {
			continue
		}
		seen[fd] = true
		resultErr = errors.Join(resultErr, file.Close())
	}
	return resultErr
}

func validPrivatePipe(file *os.File, fd uintptr, access int) error {
	if file == nil || file.Fd() != fd {
		return errors.New("private root control descriptor differs")
	}
	var st unix.Stat_t
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || unix.Fstat(int(fd), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != access {
		return errors.New("private root control pipe refused")
	}
	return nil
}

func validatePinnedSealedImage(image *PinnedSealedFile) error {
	if image == nil || image.File == nil || image.Size < 64 || image.Size > privateRootImageBudget {
		return errors.New("private root image absent or size refused")
	}
	fd := image.File.Fd()
	var st unix.Stat_t
	gotSeals, err := unix.FcntlInt(fd, unix.F_GET_SEALS, 0)
	if err != nil || unix.Fstat(int(fd), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size != image.Size || gotSeals != seals {
		return errors.New("private root image is not exactly sealed")
	}
	sum := sha256.New()
	var buf [64 << 10]byte
	for offset := int64(0); offset < image.Size; {
		size := len(buf)
		if int64(size) > image.Size-offset {
			size = int(image.Size - offset)
		}
		n, err := image.File.ReadAt(buf[:size], offset)
		if n != size || err != nil {
			return errors.New("private root image read refused")
		}
		if _, err := sum.Write(buf[:n]); err != nil {
			return err
		}
		offset += int64(n)
	}
	var got [32]byte
	copy(got[:], sum.Sum(nil))
	if got != image.SHA256 {
		return errors.New("private root image digest differs")
	}
	return nil
}

func hashPinnedImage(image *PinnedSealedFile, fd uintptr) error {
	if image == nil || image.File == nil || image.File.Fd() != fd {
		return errors.New("private root image descriptor differs")
	}
	return validatePinnedSealedImage(image)
}

func validatePrivateRootPlan(p *PrivateRootPlan) ([6]privateDevice, error) {
	var devices [6]privateDevice
	if p == nil {
		return devices, errors.New("private root plan absent")
	}
	if err := validPrivatePipe(p.Grant, 4, unix.O_RDONLY); err != nil {
		return devices, err
	}
	if err := validPrivatePipe(p.Ready, 5, unix.O_WRONLY); err != nil {
		return devices, err
	}
	images := privateRootImageRoles(p)
	var total int64
	for i, image := range images {
		if err := hashPinnedImage(image, uintptr(8+i)); err != nil {
			return devices, err
		}
		total += image.Size
		if total > privateRootImageBudget {
			return devices, errors.New("private root image aggregate exceeded")
		}
	}
	devices = privateRootDeviceRoles(p)
	for i := range devices {
		device := &devices[i]
		if device.file == nil || device.file.Fd() != device.fd {
			return devices, errors.New("private root held device descriptor differs")
		}
		flags, flagErr := unix.FcntlInt(device.fd, unix.F_GETFL, 0)
		var fs unix.Statfs_t
		st := &device.identity
		if flagErr != nil || flags&unix.O_PATH != unix.O_PATH || unix.Fstat(int(device.fd), st) != nil ||
			st.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(st.Rdev) != device.major || unix.Minor(st.Rdev) != device.minor ||
			unix.Fstatfs(int(device.fd), &fs) != nil || uint64(fs.Flags)&uint64(unix.ST_NODEV) != 0 {
			return devices, errors.New("private root held character device refused")
		}
	}
	return devices, nil
}

func privateRootGrantAndReady(p *PrivateRootPlan) error {
	if _, err := io.WriteString(p.Ready, PrivateRootReady); err != nil {
		return err
	}
	if err := p.Ready.Close(); err != nil {
		p.Ready = nil
		return err
	}
	p.Ready = nil
	raw, err := io.ReadAll(io.LimitReader(p.Grant, int64(len(PrivateRootGrant)+1)))
	if err != nil || string(raw) != PrivateRootGrant {
		return errors.New("private root GRANT absent or malformed")
	}
	if err := p.Grant.Close(); err != nil {
		p.Grant = nil
		return err
	}
	p.Grant = nil
	return nil
}

func privateRootOwnedDir(path string, mode uint32, fsType int64) (int, unix.Stat_t, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		st.Mode&07777 != mode || st.Uid != uint32(os.Getuid()) || st.Gid != uint32(os.Getgid()) || fs.Type != fsType {
		closeErr := unix.Close(fd)
		return -1, unix.Stat_t{}, errors.Join(errors.New("private root mapped directory identity refused"), closeErr)
	}
	return fd, st, nil
}

func privateRootMountTmpfs(path, options string, flags uintptr) error {
	return unix.Mount("tmpfs", path, "tmpfs", flags, options)
}

func privateRootMkdir(path string) error {
	if err := unix.Mkdir(path, 0700); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 ||
		st.Uid != uint32(os.Getuid()) || st.Gid != uint32(os.Getgid()) {
		return errors.New("private root directory creation differs")
	}
	return nil
}

func privateRootCopyImage(dirFD int, leaf string, image *PinnedSealedFile) (resultErr error) {
	fd, err := unix.Openat(dirFD, leaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0400)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "private-root-image")
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	sum := sha256.New()
	var buf [64 << 10]byte
	for offset := int64(0); offset < image.Size; {
		size := len(buf)
		if int64(size) > image.Size-offset {
			size = int(image.Size - offset)
		}
		n, err := image.File.ReadAt(buf[:size], offset)
		if n != size || err != nil {
			return errors.New("private root source image changed during copy")
		}
		if _, err := sum.Write(buf[:n]); err != nil {
			return err
		}
		written := 0
		for written < n {
			count, err := file.Write(buf[written:n])
			if count <= 0 || err != nil {
				return errors.New("private root image copy incomplete")
			}
			written += count
		}
		offset += int64(n)
	}
	var got [32]byte
	copy(got[:], sum.Sum(nil))
	if got != image.SHA256 {
		return errors.New("private root image source digest changed")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0400 ||
		st.Uid != uint32(os.Getuid()) || st.Gid != uint32(os.Getgid()) || st.Size != image.Size {
		return errors.New("private root copied image identity refused")
	}
	return nil
}

func privateRootBindDevice(devFD int, device privateDevice) (resultErr error) {
	target, err := unix.Openat(devFD, device.leaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0400)
	if err != nil {
		return err
	}
	if err := unix.Close(target); err != nil {
		return err
	}
	target, err = unix.Openat(devFD, device.leaf, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(target)) }()
	var before unix.Stat_t
	if err := unix.Fstat(target, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Uid != uint32(os.Getuid()) || before.Gid != uint32(os.Getgid()) || before.Size != 0 {
		return errors.New("private root device target refused")
	}
	tree, err := unix.OpenTree(int(device.fd), "", uint(unix.AT_EMPTY_PATH|unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC))
	if err != nil {
		return fmt.Errorf("held device clone: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(tree)) }()
	if err := unix.MountSetattr(tree, "", unix.AT_EMPTY_PATH,
		&unix.MountAttr{Attr_set: unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NOEXEC}); err != nil {
		return fmt.Errorf("held device mount restriction: %w", err)
	}
	if err := unix.MoveMount(tree, "", target, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return fmt.Errorf("held device private attachment: %w", err)
	}
	attached, err := unix.Openat(devFD, device.leaf, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(attached)) }()
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(attached, &st) != nil || unix.Fstatfs(attached, &fs) != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFCHR || st.Rdev != device.identity.Rdev ||
		st.Dev != device.identity.Dev || st.Ino != device.identity.Ino ||
		uint64(fs.Flags)&uint64(unix.ST_NODEV) != 0 || uint64(fs.Flags)&uint64(unix.ST_NOSUID|unix.ST_NOEXEC) != uint64(unix.ST_NOSUID|unix.ST_NOEXEC) {
		return errors.New("private root attached device identity or mount flags refused")
	}
	return nil
}

func privateRootVerifyLayout(rootBefore unix.Stat_t) error {
	var root, tmp, dev unix.Stat_t
	var rootFS, tmpFS, devFS, procFS unix.Statfs_t
	if unix.Stat("/", &root) != nil || unix.Stat("/tmp", &tmp) != nil || unix.Stat("/dev", &dev) != nil ||
		unix.Statfs("/", &rootFS) != nil || unix.Statfs("/tmp", &tmpFS) != nil ||
		unix.Statfs("/dev", &devFS) != nil || unix.Statfs("/proc", &procFS) != nil {
		return errors.New("private root mounted layout absent")
	}
	if root.Dev != rootBefore.Dev || root.Ino != rootBefore.Ino || root.Mode&unix.S_IFMT != unix.S_IFDIR ||
		root.Mode&07777 != 0700 || root.Uid != uint32(os.Getuid()) || root.Gid != uint32(os.Getgid()) ||
		rootFS.Type != unix.TMPFS_MAGIC || uint64(rootFS.Flags)&uint64(unix.ST_RDONLY|unix.ST_NOSUID|unix.ST_NODEV) != uint64(unix.ST_RDONLY|unix.ST_NOSUID|unix.ST_NODEV) ||
		uint64(rootFS.Flags)&uint64(unix.ST_NOEXEC) != 0 {
		return errors.New("private root read-only executable mount refused")
	}
	for _, st := range []unix.Stat_t{tmp, dev} {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 || st.Uid != uint32(os.Getuid()) || st.Gid != uint32(os.Getgid()) || st.Dev == root.Dev {
			return errors.New("private root nested mount identity refused")
		}
	}
	if tmpFS.Type != unix.TMPFS_MAGIC || uint64(tmpFS.Flags)&uint64(unix.ST_RDONLY) != 0 ||
		uint64(tmpFS.Flags)&uint64(unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC) != uint64(unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC) ||
		devFS.Type != unix.TMPFS_MAGIC || uint64(devFS.Flags)&uint64(unix.ST_RDONLY|unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC) != uint64(unix.ST_RDONLY|unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC) ||
		procFS.Type != unix.PROC_SUPER_MAGIC {
		return errors.New("private root tmp/dev/proc flags refused")
	}
	var absent unix.Stat_t
	if err := unix.Stat("/etc", &absent); !errors.Is(err, unix.ENOENT) {
		return errors.New("old root remains visible")
	}
	return nil
}

func privateRootVerifyDevices(devices [6]privateDevice) error {
	for _, device := range devices {
		fd, err := unix.Open("/dev/"+device.leaf, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		var st unix.Stat_t
		var fs unix.Statfs_t
		queryErr := errors.Join(unix.Fstat(fd, &st), unix.Fstatfs(fd, &fs), unix.Close(fd))
		if queryErr != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || st.Rdev != device.identity.Rdev ||
			st.Dev != device.identity.Dev || st.Ino != device.identity.Ino || uint64(fs.Flags)&uint64(unix.ST_NODEV) != 0 {
			return errors.New("private root device changed after pivot")
		}
	}
	nullFD, err := unix.Open("/dev/null", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("private root real null device unavailable")
	}
	var byteValue [1]byte
	n, writeErr := unix.Write(nullFD, byteValue[:])
	closeErr := unix.Close(nullFD)
	if n != 1 || writeErr != nil || closeErr != nil {
		return errors.New("private root null device behavior refused")
	}
	return nil
}

func privateRootBuild(b *nativeBootstrap, p *PrivateRootPlan, devices [6]privateDevice) (resultErr error) {
	uid, gid := os.Getuid(), os.Getgid()
	rootOptions := fmt.Sprintf("size=32m,nr_inodes=1024,mode=0700,uid=%d,gid=%d", uid, gid)
	if err := privateRootMountTmpfs("/tmp", rootOptions, unix.MS_NOSUID|unix.MS_NODEV); err != nil {
		return fmt.Errorf("private executable root mount: %w", err)
	}
	rootFD, rootBefore, err := privateRootOwnedDir("/tmp", 0700, unix.TMPFS_MAGIC)
	if err != nil {
		return err
	}
	defer func() {
		if rootFD >= 0 {
			resultErr = errors.Join(resultErr, unix.Close(rootFD))
		}
	}()
	var rootFS unix.Statfs_t
	if unix.Fstatfs(rootFD, &rootFS) != nil || uint64(rootFS.Flags)&uint64(unix.ST_NOEXEC|unix.ST_RDONLY) != 0 ||
		uint64(rootFS.Flags)&uint64(unix.ST_NOSUID|unix.ST_NODEV) != uint64(unix.ST_NOSUID|unix.ST_NODEV) {
		return errors.New("private root must be executable and initially writable")
	}
	for _, name := range []string{"/tmp/tmp", "/tmp/dev", "/tmp/proc", "/tmp/run", "/tmp/run/axis", "/tmp/run/axis/images"} {
		if err := privateRootMkdir(name); err != nil {
			return fmt.Errorf("private root fixed directory: %w", err)
		}
	}
	tmpOptions := fmt.Sprintf("size=64m,nr_inodes=4096,mode=0700,uid=%d,gid=%d", uid, gid)
	if err := privateRootMountTmpfs("/tmp/tmp", tmpOptions, unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC); err != nil {
		return fmt.Errorf("private writable tmp mount: %w", err)
	}
	tmpFD, tmpBefore, err := privateRootOwnedDir("/tmp/tmp", 0700, unix.TMPFS_MAGIC)
	if err != nil {
		return err
	}
	defer func() {
		if tmpFD >= 0 {
			resultErr = errors.Join(resultErr, unix.Close(tmpFD))
		}
	}()
	if tmpBefore.Dev == rootBefore.Dev {
		return errors.New("private tmp is not a separate mount")
	}
	devOptions := fmt.Sprintf("size=1m,nr_inodes=64,mode=0700,uid=%d,gid=%d", uid, gid)
	if err := privateRootMountTmpfs("/tmp/dev", devOptions, unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC); err != nil {
		return fmt.Errorf("private device directory mount: %w", err)
	}
	devFD, devBefore, err := privateRootOwnedDir("/tmp/dev", 0700, unix.TMPFS_MAGIC)
	if err != nil {
		return err
	}
	defer func() {
		if devFD >= 0 {
			resultErr = errors.Join(resultErr, unix.Close(devFD))
		}
	}()
	if devBefore.Dev == rootBefore.Dev || devBefore.Dev == tmpBefore.Dev {
		return errors.New("private device directory is not a separate mount")
	}
	imageFD, _, err := privateRootOwnedDir("/tmp/run/axis/images", 0700, unix.TMPFS_MAGIC)
	if err != nil {
		return err
	}
	defer func() {
		if imageFD >= 0 {
			resultErr = errors.Join(resultErr, unix.Close(imageFD))
		}
	}()
	images := privateRootImageRoles(p)
	for i, leaf := range [3]string{"peer", "bubblewrap", "payload"} {
		if err := privateRootCopyImage(imageFD, leaf, images[i]); err != nil {
			return fmt.Errorf("private runtime image %d: %w", i, err)
		}
	}
	for _, device := range devices {
		if err := privateRootBindDevice(devFD, device); err != nil {
			return fmt.Errorf("private held device %s: %w", device.leaf, err)
		}
	}
	procTarget, err := unix.Open("/tmp/proc", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var procSt unix.Stat_t
	if unix.Fstat(procTarget, &procSt) != nil || procSt.Dev != rootBefore.Dev || procSt.Mode&unix.S_IFMT != unix.S_IFDIR ||
		procSt.Mode&07777 != 0700 || procSt.Uid != uint32(uid) || procSt.Gid != uint32(gid) {
		closeErr := unix.Close(procTarget)
		return errors.Join(errors.New("private proc destination identity refused"), closeErr)
	}
	if err := unix.MoveMount(b.proc, "", procTarget, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		closeErr := unix.Close(procTarget)
		return errors.Join(fmt.Errorf("held fresh proc move: %w", err), closeErr)
	}
	if err := unix.Close(procTarget); err != nil {
		return err
	}
	var procFS unix.Statfs_t
	if unix.Statfs("/tmp/proc", &procFS) != nil || procFS.Type != unix.PROC_SUPER_MAGIC {
		return errors.New("moved fresh proc refused")
	}
	if err := closePrivateRootPlan(p); err != nil {
		return fmt.Errorf("old-root source closure: %w", err)
	}
	if err := unix.MountSetattr(devFD, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}); err != nil {
		return fmt.Errorf("private device directory readonly: %w", err)
	}
	if err := unix.MountSetattr(rootFD, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}); err != nil {
		return fmt.Errorf("private root readonly: %w", err)
	}
	if err := unix.Fchdir(rootFD); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("private root pivot: %w", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("old root detach: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	for _, fd := range []*int{&imageFD, &devFD, &tmpFD, &rootFD} {
		current := *fd
		*fd = -1
		if err := unix.Close(current); err != nil {
			return err
		}
	}
	if err := privateRootVerifyLayout(rootBefore); err != nil {
		return err
	}
	if err := privateRootVerifyDevices(devices); err != nil {
		return err
	}
	probe, err := unix.Open("/tmp/.axis-writable-proof", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("private tmp is not writable")
	}
	closeErr := unix.Close(probe)
	unlinkErr := unix.Unlink("/tmp/.axis-writable-proof")
	if closeErr != nil || unlinkErr != nil {
		return errors.New("private tmp write proof cleanup refused")
	}
	rootProbe, err := unix.Open("/.axis-readonly-proof", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err == nil {
		closeErr := unix.Close(rootProbe)
		return errors.Join(errors.New("private root unexpectedly writable"), closeErr)
	}
	if !errors.Is(err, unix.EROFS) {
		return errors.New("private root readonly proof inconclusive")
	}
	return nil
}

// SetupPrivateRoot consumes its typed handles and FD3 on every path. It sends
// READY only after kernel namespace and capability-source validation, and it
// performs no mount until the exact creating-thread owner sends GRANT. The
// caller must leave the whole PID namespace on any error.
func SetupPrivateRoot(plan *PrivateRootPlan) (resultErr error) {
	runtime.LockOSThread()
	if plan == nil {
		return errors.New("private root plan absent")
	}
	owned := *plan
	*plan = PrivateRootPlan{}
	defer func() { resultErr = errors.Join(resultErr, closePrivateRootPlan(&owned)) }()
	if runtime.GOARCH != "amd64" || os.Getpid() != 1 || os.Getppid() != 0 ||
		unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0) != nil {
		return errors.New("private namespace init required")
	}
	proofFile := os.NewFile(3, "private-namespace-proof")
	if proofFile == nil {
		return errors.New("private namespace proof missing")
	}
	defer func() {
		if proofFile != nil {
			resultErr = errors.Join(resultErr, proofFile.Close())
		}
	}()
	info, err := proofFile.Stat()
	gotSeals, sealErr := unix.FcntlInt(proofFile.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || sealErr != nil || !info.Mode().IsRegular() || info.Size() != proofSize || gotSeals != seals {
		return errors.New("sealed namespace proof required")
	}
	var data [proofSize]byte
	if n, err := proofFile.ReadAt(data[:], 0); err != nil || n != len(data) {
		return errors.New("namespace proof read refused")
	}
	parent, err := decode(data[:])
	if err != nil {
		return err
	}
	if err := proofFile.Close(); err != nil {
		proofFile = nil
		return err
	}
	proofFile = nil
	b := &nativeBootstrap{parent: parent, fds: [3]int{-1, -1, -1}, proc: -1}
	defer func() {
		for i := range b.fds {
			if b.fds[i] >= 0 {
				resultErr = errors.Join(resultErr, unix.Close(b.fds[i]))
				b.fds[i] = -1
			}
		}
		if b.proc >= 0 {
			resultErr = errors.Join(resultErr, unix.Close(b.proc))
			b.proc = -1
		}
	}()
	if err := b.validate(); err != nil {
		return fmt.Errorf("owned namespace proof: %w", err)
	}
	devices, err := validatePrivateRootPlan(&owned)
	if err != nil {
		return err
	}
	if err := privateRootGrantAndReady(&owned); err != nil {
		return err
	}
	if err := b.privateMounts(); err != nil {
		return fmt.Errorf("private propagation: %w", err)
	}
	if err := b.mountProc(); err != nil {
		return fmt.Errorf("fresh proc before pivot: %w", err)
	}
	if err := privateRootBuild(b, &owned, devices); err != nil {
		return err
	}
	if err := b.dropCaps(); err != nil {
		return fmt.Errorf("all-thread capability drop: %w", err)
	}
	if err := b.verify(); err != nil {
		return fmt.Errorf("private namespace and capability verification: %w", err)
	}
	return nil
}
