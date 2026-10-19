// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// newNativeSandboxHookAssets consumes the binding only when it returns a
// nonnil owner (including with error). parent remains borrowed; its independent
// duplicate is retained by the owner. identity must be the manager's reserved
// full SessionIdentity; harness/surface are trusted admitted installation facts,
// never a hook request, profile label, name lookup or caller-supplied receipt.
// This does not certify that any harness/contract can enforce native hooks.
func (a *APIServer) newNativeSandboxHookAssets(ctx context.Context, identity sandboxruntime.SessionIdentity,
	harness sandboxruntime.HarnessIdentity, surface, bindingID, token string, parent *os.File,
) (*nativeSandboxHookAssets, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || identity.Validate() != nil || harness.Validate() != nil || identity.Runtime.Runtime != sandboxruntime.Axis ||
		identity.Runtime.HostOS != "linux" || identity.Runtime.ExecutionOS != "linux" || identity.Runtime.Backend != "mxc" ||
		identity.Runtime.Driver != "bubblewrap" || parent == nil || os.Getuid() <= 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return nil, errNativeHookAssets
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 24*time.Hour {
		return nil, errNativeHookAssets
	}
	state := a.sandboxIngressState()
	if state == nil {
		return nil, errNativeHookAssets
	}
	store, ok := state.bindings.(*sandboxauth.FileStore)
	if !ok || store == nil {
		return nil, errNativeHookAssets
	}
	binding, err := store.Match(token)
	if err != nil || binding.ID != bindingID || binding.SandboxID != identity.ID || binding.SandboxName != identity.Name ||
		binding.ExecutionOS != "linux" || binding.HookContractID != harness.HookContract || binding.AgentVersion != harness.Version ||
		binding.Workdir.Mode != sandboxauth.WorkdirCopy || len(binding.Workdir.Mounts) != 0 || len(binding.Routes) != 1 || binding.Routes[0] != sandboxauth.RouteHook ||
		binding.ExpiresAt.IsZero() || !binding.ExpiresAt.After(time.Now()) || binding.ExpiresAt.After(deadline) {
		return nil, errNativeHookAssets
	}
	profile := hookexec.NativeSandboxProfile{Version: 1, SessionID: identity.ID, Connector: binding.Connector,
		HookContract: binding.HookContractID, HookSurface: surface}
	if profile.Validate() != nil {
		return nil, errNativeHookAssets
	}
	raw, err := json.Marshal(profile)
	if err != nil || len(raw) > 4096 {
		return nil, errNativeHookAssets
	}
	digest := sha256.Sum256(raw)
	files := &nativeHookLinuxFiles{profileBytes: raw}
	assets := &nativeSandboxHookAssets{op: make(chan struct{}, 1), identity: identity, harness: harness, lifetime: ctx, connector: binding.Connector,
		contract: binding.HookContractID, bindingID: binding.ID, digest: "sha256:" + hex.EncodeToString(digest[:])}
	var endpoint *nativeSandboxHookIngress
	assets.seal = func() {
		if endpoint != nil {
			endpoint.sealAdmission()
		}
	}
	assets.admission = func() bool {
		if endpoint == nil {
			return false
		}
		endpoint.mu.Lock()
		defer endpoint.mu.Unlock()
		return !endpoint.closing && endpoint.ctx.Err() == nil && a.sandboxIngressState() == endpoint.state
	}
	assets.revoke = func(cleanup context.Context) error {
		if endpoint != nil {
			return endpoint.closeAdmission(cleanup)
		}
		if err := store.Revoke(binding.ID); err != nil && !errors.Is(err, sandboxauth.ErrNotFound) {
			return errNativeHookAssets
		}
		return nil
	}
	assets.drain = func(cleanup context.Context) error {
		if endpoint != nil {
			return endpoint.Close(cleanup)
		}
		return files.closeListener()
	}
	assets.release, assets.duplicate = files.close, files.duplicate
	if err := files.create(parent); err != nil {
		return assets, errors.Join(errNativeHookAssets, err)
	}
	endpoint, err = a.newNativeSandboxHookIngress(ctx, files.listener, identity.ID, binding.ID, token)
	if err != nil {
		return assets, err
	}
	files.listener = nil // endpoint now owns the listener; root pins stay here
	return assets, nil
}

type nativeHookLinuxIdentity struct {
	dev, ino, mount   uint64
	mode, uid         uint32
	links             uint64
	size              int64
	modified, changed unix.Timespec
}

func nativeHookLinuxInfo(file *os.File, kind uint32, mode uint32) (nativeHookLinuxIdentity, error) {
	if file == nil {
		return nativeHookLinuxIdentity{}, errNativeHookAssets
	}
	fd := int(file.Fd())
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		return nativeHookLinuxIdentity{}, errNativeHookAssets
	}
	var info unix.Stat_t
	var mount unix.Statx_t
	var filesystem unix.Statfs_t
	if unix.Fstat(fd, &info) != nil || unix.Fstatfs(fd, &filesystem) != nil ||
		info.Mode&unix.S_IFMT != kind || info.Mode&0o7777 != mode || info.Uid != uint32(os.Geteuid()) || info.Nlink == 0 ||
		kind != unix.S_IFDIR && info.Nlink != 1 || info.Size < 0 {
		return nativeHookLinuxIdentity{}, errNativeHookAssets
	}
	switch filesystem.Type {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC:
	default:
		return nativeHookLinuxIdentity{}, errNativeHookAssets
	}
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &mount) != nil ||
		mount.Mask&unix.STATX_MNT_ID == 0 || mount.Mnt_id == 0 {
		return nativeHookLinuxIdentity{}, errNativeHookAssets
	}
	return nativeHookLinuxIdentity{info.Dev, info.Ino, mount.Mnt_id, info.Mode, info.Uid, uint64(info.Nlink), info.Size, info.Mtim, info.Ctim}, nil
}

func (id nativeHookLinuxIdentity) sameObject(other nativeHookLinuxIdentity) bool {
	return id.dev == other.dev && id.ino == other.ino && id.mount == other.mount && id.mode == other.mode && id.uid == other.uid && id.links == other.links
}

func nativeHookLinuxCreated(file *os.File, kind uint32) (nativeHookLinuxIdentity, error) {
	var info unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &info) != nil {
		return nativeHookLinuxIdentity{}, errNativeHookAssets
	}
	return nativeHookLinuxInfo(file, kind, info.Mode&0o7777)
}

type nativeHookLinuxFiles struct {
	parent, root, profile, socket, writer           *os.File
	listener                                        *net.UnixListener
	name                                            string
	parentID, rootID, profileID, socketID           nativeHookLinuxIdentity
	profileBytes                                    []byte
	extra                                           []*os.File
	sticky                                          error
	closeNative                                     func(*os.File) error // private uncertain-close test seam
	created, profileCreated, socketCreated, removed bool
}

func (files *nativeHookLinuxFiles) closeFile(file **os.File) error {
	if *file == nil {
		return nil
	}
	closeFile := files.closeNative
	if closeFile == nil {
		closeFile = (*os.File).Close
	}
	if err := closeFile(*file); err != nil {
		files.sticky = errors.Join(files.sticky, errNativeHookAssets)
		return files.sticky
	}
	*file = nil
	return nil
}

func (files *nativeHookLinuxFiles) closeLastExtra() error {
	if err := files.closeFile(&files.extra[len(files.extra)-1]); err != nil {
		return err
	}
	files.extra = files.extra[:len(files.extra)-1]
	return nil
}

func nativeHookLinuxOpen(parent *os.File, leaf string, flags uint64, mode uint64) (*os.File, error) {
	if parent == nil || (leaf != "runtime.json" && leaf != "ingress.sock" && leaf != "." && (len(leaf) != 36 || leaf[:4] != "dch-")) {
		return nil, errNativeHookAssets
	}
	how := &unix.OpenHow{Flags: flags | unix.O_CLOEXEC | unix.O_NOFOLLOW, Mode: mode,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV}
	fd, err := unix.Openat2(int(parent.Fd()), leaf, how)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "native-hook-held-object"), nil
}

func (files *nativeHookLinuxFiles) create(parent *os.File) error {
	id, err := nativeHookLinuxInfo(parent, unix.S_IFDIR, 0o700)
	if err != nil {
		return err
	}
	fd, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	files.parent, files.parentID = os.NewFile(uintptr(fd), "native-hook-held-parent"), id
	if after, err := nativeHookLinuxInfo(files.parent, unix.S_IFDIR, 0o700); err != nil || !id.sameObject(after) {
		return errNativeHookAssets
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	files.name = "dch-" + hex.EncodeToString(random[:])
	if err := unix.Mkdirat(fd, files.name, 0o700); err != nil {
		return err
	}
	files.created = true
	files.root, err = nativeHookLinuxOpen(files.parent, files.name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		files.sticky = errNativeHookAssets
		return err
	}
	files.rootID, err = nativeHookLinuxInfo(files.root, unix.S_IFDIR, 0o700)
	if err != nil || files.rootID.mount != id.mount {
		files.sticky = errNativeHookAssets
		return errNativeHookAssets
	}
	files.writer, err = nativeHookLinuxOpen(files.root, "runtime.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	files.profileCreated = true
	files.profileID, err = nativeHookLinuxCreated(files.writer, unix.S_IFREG)
	if err != nil {
		files.sticky = errNativeHookAssets
		return err
	}
	if n, err := files.writer.Write(files.profileBytes); err != nil || n != len(files.profileBytes) {
		return errors.Join(errNativeHookAssets, err)
	}
	if err := files.writer.Chmod(0o400); err != nil {
		return err
	}
	before, err := nativeHookLinuxInfo(files.writer, unix.S_IFREG, 0o400)
	if err != nil {
		files.sticky = errNativeHookAssets
		return err
	}
	files.profileID = before
	if err := files.writer.Sync(); err != nil {
		return err
	}
	files.profile, err = nativeHookLinuxOpen(files.root, "runtime.json", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	after, err := nativeHookLinuxInfo(files.profile, unix.S_IFREG, 0o400)
	if err != nil || !before.sameObject(after) {
		files.sticky = errNativeHookAssets
		return errNativeHookAssets
	}
	if err := files.closeFile(&files.writer); err != nil {
		return err
	}
	// The sole intentional numeric capability alias is verified as current
	// procfs before net.ListenUnix follows it. No display path/TreePath enters.
	var pid [12]byte
	n, err := unix.Readlink("/proc/self", pid[:])
	if err != nil || n >= len(pid) || string(pid[:n]) != strconv.Itoa(os.Getpid()) {
		return errNativeHookAssets
	}
	procFD, err := unix.Open("/proc/self/fd", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	proc := os.NewFile(uintptr(procFD), "native-hook-proc-fds")
	files.extra = append(files.extra, proc)
	var procFS unix.Statfs_t
	if unix.Fstatfs(procFD, &procFS) != nil || procFS.Type != unix.PROC_SUPER_MAGIC {
		return errNativeHookAssets
	}
	alias := fmt.Sprintf("/proc/self/fd/%d/ingress.sock", files.root.Fd())
	files.listener, err = net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: alias})
	if files.listener != nil {
		files.listener.SetUnlinkOnClose(false)
	}
	// Even a Listen failure after bind must retain the exact filesystem socket.
	var openErr error
	files.socket, openErr = nativeHookLinuxOpen(files.root, "ingress.sock", unix.O_PATH, 0)
	if openErr == nil {
		files.socketCreated = true
		files.socketID, openErr = nativeHookLinuxCreated(files.socket, unix.S_IFSOCK)
		if openErr != nil {
			files.sticky = errNativeHookAssets
			return openErr
		}
		if chmodErr := unix.Fchmodat(int(files.root.Fd()), "ingress.sock", 0o600, unix.AT_SYMLINK_NOFOLLOW); chmodErr != nil {
			return chmodErr
		}
		files.socketID, openErr = nativeHookLinuxInfo(files.socket, unix.S_IFSOCK, 0o600)
	} else if !errors.Is(openErr, unix.ENOENT) {
		files.sticky = errNativeHookAssets
	}
	if err != nil || openErr != nil {
		return errors.Join(err, openErr)
	}
	if err := files.root.Sync(); err != nil {
		return err
	}
	return files.validate()
}

func (files *nativeHookLinuxFiles) validate() error {
	if files.sticky != nil || files.root == nil || files.profile == nil || files.socket == nil {
		return errNativeHookAssets
	}
	id, err := nativeHookLinuxInfo(files.root, unix.S_IFDIR, 0o700)
	if err != nil || !files.rootID.sameObject(id) {
		return errNativeHookAssets
	}
	rootEntry, err := nativeHookLinuxOpen(files.parent, files.name, unix.O_PATH, 0)
	if err != nil {
		return err
	}
	files.extra = append(files.extra, rootEntry)
	entryID, err := nativeHookLinuxInfo(rootEntry, unix.S_IFDIR, 0o700)
	if err != nil || !files.rootID.sameObject(entryID) {
		return errNativeHookAssets
	}
	if err := files.closeLastExtra(); err != nil {
		return err
	}
	for _, item := range []struct {
		file       *os.File
		leaf       string
		kind, mode uint32
		expected   nativeHookLinuxIdentity
	}{
		{files.profile, "runtime.json", unix.S_IFREG, 0o400, files.profileID},
		{files.socket, "ingress.sock", unix.S_IFSOCK, 0o600, files.socketID},
	} {
		id, err := nativeHookLinuxInfo(item.file, item.kind, item.mode)
		if err != nil || !item.expected.sameObject(id) || id.mount != files.rootID.mount {
			return errNativeHookAssets
		}
		pin, err := nativeHookLinuxOpen(files.root, item.leaf, unix.O_PATH, 0)
		if err != nil {
			return err
		}
		files.extra = append(files.extra, pin)
		entry, err := nativeHookLinuxInfo(pin, item.kind, item.mode)
		if err != nil || !id.sameObject(entry) {
			return errNativeHookAssets
		}
		if err := files.closeLastExtra(); err != nil {
			return err
		}
	}
	before, err := nativeHookLinuxInfo(files.profile, unix.S_IFREG, 0o400)
	if err != nil || before.size != int64(len(files.profileBytes)) {
		return errNativeHookAssets
	}
	raw := make([]byte, len(files.profileBytes)+1)
	n, readErr := files.profile.ReadAt(raw, 0)
	after, err := nativeHookLinuxInfo(files.profile, unix.S_IFREG, 0o400)
	if err != nil || before != after || n != len(files.profileBytes) || readErr != io.EOF || sha256.Sum256(raw[:n]) != sha256.Sum256(files.profileBytes) {
		return errNativeHookAssets
	}
	return files.entries(false)
}

func (files *nativeHookLinuxFiles) entries(empty bool) error {
	reader, err := nativeHookLinuxOpen(files.root, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	files.extra = append(files.extra, reader)
	readErr := exactNativeHookEntries(reader.Readdirnames, empty)
	return errors.Join(readErr, files.closeLastExtra())
}

func (files *nativeHookLinuxFiles) duplicate() (*os.File, error) {
	if err := files.validate(); err != nil {
		return nil, err
	}
	fd, err := unix.FcntlInt(files.root.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "native-hook-exclusive-grant")
	id, err := nativeHookLinuxInfo(file, unix.S_IFDIR, 0o700)
	if err != nil || !files.rootID.sameObject(id) {
		files.extra = append(files.extra, file)
		return nil, errNativeHookAssets
	}
	return file, nil
}

func (files *nativeHookLinuxFiles) closeListener() error {
	if files.listener == nil {
		return nil
	}
	if err := files.listener.Close(); err != nil {
		files.sticky = errNativeHookAssets
		return files.sticky
	}
	files.listener = nil
	return nil
}

func (files *nativeHookLinuxFiles) close() error {
	if files.sticky != nil {
		return files.sticky
	}
	if err := files.closeListener(); err != nil {
		return err
	}
	if files.profile == nil && files.profileCreated {
		// A pre-publication failure may still own only the writer. Keep that
		// exact pin through identity-checked unlink; never lose it on error.
		files.profile, files.writer = files.writer, nil
	} else if err := files.closeFile(&files.writer); err != nil {
		return err
	}
	for i := range files.extra {
		if err := files.closeFile(&files.extra[i]); err != nil {
			return err
		}
	}
	files.extra = nil
	if files.created && !files.removed {
		if files.root == nil || files.rootID.ino == 0 {
			return errNativeHookAssets
		}
		for _, item := range []struct {
			file       **os.File
			leaf       string
			kind, mode uint32
			expected   nativeHookLinuxIdentity
			created    *bool
		}{
			{&files.socket, "ingress.sock", unix.S_IFSOCK, 0o600, files.socketID, &files.socketCreated},
			{&files.profile, "runtime.json", unix.S_IFREG, 0o400, files.profileID, &files.profileCreated},
		} {
			if !*item.created {
				continue
			}
			if *item.file == nil || item.expected.ino == 0 {
				return errNativeHookAssets
			}
			pin, err := nativeHookLinuxOpen(files.root, item.leaf, unix.O_PATH, 0)
			if err != nil {
				return err
			}
			files.extra = append(files.extra, pin)
			id, err := nativeHookLinuxInfo(pin, item.kind, item.expected.mode&0o7777)
			if err != nil || !item.expected.sameObject(id) {
				return errNativeHookAssets
			}
			if err := files.closeLastExtra(); err != nil {
				return err
			}
			if err := unix.Unlinkat(int(files.root.Fd()), item.leaf, 0); err != nil {
				return err
			}
			*item.created = false
			if err := files.closeFile(item.file); err != nil {
				return err
			}
		}
		if err := files.entries(true); err != nil {
			return err
		}
		pin, err := nativeHookLinuxOpen(files.parent, files.name, unix.O_PATH, 0)
		if err != nil {
			return err
		}
		files.extra = append(files.extra, pin)
		id, err := nativeHookLinuxInfo(pin, unix.S_IFDIR, 0o700)
		if err != nil || !files.rootID.sameObject(id) {
			return errNativeHookAssets
		}
		if err := files.closeLastExtra(); err != nil {
			return err
		}
		if err := unix.Unlinkat(int(files.parent.Fd()), files.name, unix.AT_REMOVEDIR); err != nil {
			return err
		}
		files.removed = true
	}
	if err := files.closeFile(&files.root); err != nil {
		return err
	}
	return files.closeFile(&files.parent)
}
