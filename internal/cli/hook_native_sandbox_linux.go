// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"errors"
	"io"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"golang.org/x/sys/unix"
)

var errNativeHookProfile = errors.New("native sandbox hook runtime unavailable")

func nativeHookLocalFilesystem(file int) (unix.Statfs_t, error) {
	var filesystem unix.Statfs_t
	if unix.Fstatfs(file, &filesystem) != nil {
		return filesystem, errNativeHookProfile
	}
	switch uint64(filesystem.Type) {
	case unix.EXT4_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC:
		return filesystem, nil
	default:
		return filesystem, errNativeHookProfile
	}
}

func sameNativeHookFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink &&
		a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// This is a Linux guest-layout resolver, not a production capability receipt.
// The factory must separately bind this exact two-entry readonly directory to
// the typed native Hook capability and retain its custody until native cleanup.
func loadNativeSandboxHookProfile() (*hookexec.NativeSandboxProfile, bool, error) {
	root, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, true, errNativeHookProfile
	}
	defer unix.Close(root)
	current := root
	// Each fixed positive component is terminal in its O_PATH lookup. There is
	// no trailing slash/O_DIRECTORY or uncached multi-component traversal.
	for _, component := range []string{"run", "defenseclaw-hook"} {
		next, err := unix.Openat(current, component, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if current != root {
			_ = unix.Close(current)
		}
		if errors.Is(err, unix.ENOENT) {
			return nil, false, nil // no native runtime on an ordinary host
		}
		if err != nil {
			return nil, true, errNativeHookProfile
		}
		current = next
		var metadata unix.Stat_t
		if unix.Fstat(current, &metadata) != nil || metadata.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(current)
			return nil, true, errNativeHookProfile
		}
		if _, err := nativeHookLocalFilesystem(current); err != nil {
			_ = unix.Close(current)
			return nil, true, errNativeHookProfile
		}
	}
	defer unix.Close(current)
	var directory unix.Stat_t
	filesystem, err := nativeHookLocalFilesystem(current)
	if err != nil || unix.Fstat(current, &directory) != nil || directory.Uid != uint32(os.Geteuid()) ||
		directory.Mode&0o7777 != 0o700 || filesystem.Flags&unix.ST_RDONLY == 0 {
		return nil, true, errNativeHookProfile
	}
	fileFD, err := unix.Openat(current, "runtime.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, true, errNativeHookProfile
	}
	file := os.NewFile(uintptr(fileFD), "fixed-native-hook-profile")
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	var before, after unix.Stat_t
	fileFS, fsErr := nativeHookLocalFilesystem(fileFD)
	if fsErr != nil || fileFS.Flags&unix.ST_RDONLY == 0 || unix.Fstat(fileFD, &before) != nil ||
		before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0o7777 != 0o400 || before.Nlink != 1 ||
		before.Uid != directory.Uid || before.Dev != directory.Dev || before.Size <= 0 || before.Size > 4096 {
		return nil, true, errNativeHookProfile
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, 4097))
	if readErr != nil || len(raw) != int(before.Size) || unix.Fstat(fileFD, &after) != nil || !sameNativeHookFile(before, after) {
		return nil, true, errNativeHookProfile
	}
	closed = true
	if err := file.Close(); err != nil {
		return nil, true, errNativeHookProfile
	}
	profile, err := hookexec.DecodeNativeSandboxProfile(raw)
	if err != nil {
		return nil, true, errNativeHookProfile
	}
	return profile, true, nil
}
