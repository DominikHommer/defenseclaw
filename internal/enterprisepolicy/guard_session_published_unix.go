//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// publishedSessionFileMode makes a record readable through the per-user
// folder's access-list entry: the folder (0700 plus one read entry for the
// account) is what keeps other accounts out.
func publishedSessionFileMode(file *os.File) error { return file.Chmod(0o644) }

// expirePublishedSessionRecord sets the modification time of the record at
// path to publishedSessionRevokedTime (revokePublishedSessionRecord). Only a
// regular file is changed: the record folder is the gateway's own.
func expirePublishedSessionRecord(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return os.Chtimes(path, publishedSessionRevokedTime, publishedSessionRevokedTime)
}

// publishedSessionGrantReader gives uid read and search on the per-user
// folder dir (replaceable in tests, which cannot change access lists).
var publishedSessionGrantReader = grantPublishedSessionReader

// publishedSessionPrepare makes dir, below the lifecycle's root, a folder
// of this process (the gateway service account) that only the account
// identity (a decimal uid) can also read. A folder that is not this
// process's own is replaced.
func publishedSessionPrepare(root, dir, identity string) error {
	self := uint32(os.Geteuid())
	if err := publishedSessionOwnDir(root, self, true); err != nil {
		return fmt.Errorf("protected session record root %s: %w", root, err)
	}
	uid, err := strconv.ParseUint(identity, 10, 32)
	if err != nil {
		return fmt.Errorf("protected session record: identity %q is not a uid", identity)
	}
	for attempt := 0; attempt < 2; attempt++ {
		_, err := os.Lstat(dir)
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				if errors.Is(err, fs.ErrExist) {
					continue
				}
				return err
			}
			if err := os.Chmod(dir, 0o700); err != nil {
				_ = os.Remove(dir)
				return err
			}
			if err := publishedSessionGrantReader(dir, uint32(uid)); err != nil {
				_ = os.Remove(dir)
				return fmt.Errorf("grant uid %d read access to %s: %w", uid, dir, err)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if publishedSessionOwnDir(dir, self, false) == nil {
			return nil
		}
		// Not a folder this gateway made (or its owner or mode drifted):
		// replace it, so a record never lands where another account could
		// change it.
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	return fmt.Errorf("protected session record folder %s keeps changing", dir)
}

// publishedSessionOwnDir checks a folder this process writes records in: a
// real folder owned by this process's uid (or, for the root folder the
// lifecycle created, by root), that no group or other can write.
func publishedSessionOwnDir(path string, self uint32, rootOwnerOK bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s is not a folder", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or other (%04o)", path, info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", path)
	}
	if st.Uid != self && (!rootOwnerOK || st.Uid != 0) {
		return fmt.Errorf("%s is owned by uid %d", path, st.Uid)
	}
	return nil
}

// ValidatePublishedSessionPath checks a protected session record before the
// hook reads it: the record and every folder above it are real files and
// folders owned by root or the gateway service uid (from the root-owned
// runtime descriptor, never from the environment), writable by no group or
// other, with no access-list entry that grants write.
func ValidatePublishedSessionPath(path string, trust PublishedSessionTrust) error {
	return validatePublishedSessionWalk(path, false, trust)
}

// validatePublishedSessionFolder checks a folder of the record tree and
// every folder above it the way ValidatePublishedSessionPath checks a record
// (PublishedSessionTreeProblem).
func validatePublishedSessionFolder(path string, trust PublishedSessionTrust, _ int) error {
	return validatePublishedSessionWalk(path, true, trust)
}

func validatePublishedSessionWalk(path string, folder bool, trust PublishedSessionTrust) error {
	clean, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for cur, leaf := clean, true; ; cur, leaf = filepath.Dir(cur), false {
		info, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symbolic link", cur)
		}
		if file := leaf && !folder; file && !info.Mode().IsRegular() || !file && !info.IsDir() {
			return fmt.Errorf("%s is not a regular %s", cur, map[bool]string{true: "file", false: "folder"}[file])
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by group or other (%04o)", cur, info.Mode().Perm())
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: cannot read its owner", cur)
		}
		if st.Uid != 0 && (trust.ServiceUID <= 0 || st.Uid != uint32(trust.ServiceUID)) {
			return fmt.Errorf("%s is owned by uid %d, not root or the gateway service account", cur, st.Uid)
		}
		if err := managed.ValidatePathACL(cur); err != nil {
			return err
		}
		if cur == filepath.Dir(cur) {
			return nil
		}
	}
}

// publishedSessionPendingFlag reports the guardian's pending mark on an
// account's private session store (MarkForeignHookRemovalPending): its
// sticky bit, which only root and the folder's owner, the gateway service,
// can set, and which nothing else in the store uses.
func publishedSessionPendingFlag(info os.FileInfo) bool { return info.Mode()&os.ModeSticky != 0 }

// publishedSessionSetPending sets or clears the pending mark of dir. A mode
// change needs no free space, and it keeps the folder's access-list entry.
func publishedSessionSetPending(dir string, on bool) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a folder", dir)
	}
	mode := info.Mode().Perm()
	if on {
		mode |= os.ModeSticky
	}
	return os.Chmod(dir, mode)
}

// publishedSessionCreatePendingDir creates the private session store the
// guardian marks for an account that has none, and the store folder above
// it: 0700 and owned like the data directory dataDir (the gateway service),
// so the gateway can use the store once the mark is cleared.
func publishedSessionCreatePendingDir(dataDir, dir string) error {
	info, err := os.Lstat(dataDir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok {
		return fmt.Errorf("%s is not a folder", dataDir)
	}
	for _, path := range []string{filepath.Dir(dir), dir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return err
		}
		if err := os.Lchown(path, int(st.Uid), int(st.Gid)); err != nil {
			return err
		}
	}
	return nil
}
