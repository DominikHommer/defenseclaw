// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// Releases 0.8.10 through 1.0.3 unlink a lock file whose modification time
// is more than 60 seconds old before they open it, and unlink it again after
// they unlock it. A sentinel this release keeps would look stale to them a
// minute after it was made, and they would take a new inode while this
// release still held the old one. Each holder therefore stamps the sentinel's
// modification time this far ahead of now, so an older writer that runs
// during an upgrade or after a rollback never takes it for stale.
const lockSentinelStampLead = 365 * 24 * time.Hour

// withFileLock acquires an exclusive advisory lock on path+".lock" before
// running fn, and releases it when fn returns. The sentinel stays at the
// same pathname so a waiting writer never locks an unlinked inode.
func withFileLock(path string, fn func() error) error {
	return withFileLockMode(path, false, fn)
}

func withFileLockMode(path string, _ bool, fn func() error) error {
	lockPath := path + ".lock"
	// An older writer unlinks the sentinel after it unlocks. A contender can
	// open that old inode before it is unlinked and acquire its flock
	// afterward. Confirm the pathname still names our locked inode, stamped,
	// before entering the critical section; otherwise reopen and retry.
	for attempt := 0; attempt < 8; attempt++ {
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("open lock file %s: %w", lockPath, err)
		}
		if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
			_ = lockFile.Close()
			return fmt.Errorf("acquire lock %s: %w", lockPath, err)
		}
		release := func() {
			_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			_ = lockFile.Close()
		}
		held, err := stampHeldLockSentinel(lockPath, lockFile)
		if err != nil {
			release()
			return err
		}
		if !held {
			release()
			continue
		}
		fnErr := fn()
		// The lock excluded every other writer only if the pathname still
		// names this inode: once an older writer unlinked it, the next one
		// made a new inode and may have run beside fn. Report that instead
		// of a success nobody can prove.
		held, heldErr := lockPathNamesFile(lockPath, lockFile)
		release()
		if heldErr == nil && !held {
			heldErr = fmt.Errorf("lock file %s was unlinked or replaced while this writer held it, so another writer may have run at the same time; check the result and retry", lockPath)
		}
		switch {
		case heldErr == nil:
			return fnErr
		case fnErr == nil:
			return heldErr
		default:
			return errors.Join(fnErr, heldErr)
		}
	}
	return fmt.Errorf("lock path %s changed while acquiring; retry the operation", lockPath)
}

// stampHeldLockSentinel stamps lockFile's modification time
// lockSentinelStampLead ahead and reports whether lockPath still names it.
// The stamp is set through the pathname and proven on the locked inode: a
// sentinel that does not read back as stamped, or that the pathname no longer
// names, is not entered.
func stampHeldLockSentinel(lockPath string, lockFile *os.File) (bool, error) {
	stamp := time.Now().Add(lockSentinelStampLead)
	if err := os.Chtimes(lockPath, stamp, stamp); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stamp lock file %s: %w", lockPath, err)
	}
	info, err := lockFile.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect lock file %s: %w", lockPath, err)
	}
	if !info.ModTime().After(time.Now().Add(lockSentinelStampLead / 2)) {
		// Either the pathname named another inode when it was stamped, or
		// the file system did not keep the stamp.
		if held, err := lockPathNamesFile(lockPath, lockFile); err != nil || !held {
			return false, err
		}
		return false, fmt.Errorf("stamp lock file %s: its modification time reads back as %s, so an older writer could take it for stale", lockPath, info.ModTime().UTC().Format(time.RFC3339))
	}
	return lockPathNamesFile(lockPath, lockFile)
}

// lockPathNamesFile reports whether lockPath names lockFile's inode.
func lockPathNamesFile(lockPath string, lockFile *os.File) (bool, error) {
	lockedInfo, err := lockFile.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect lock file %s: %w", lockPath, err)
	}
	pathInfo, err := os.Stat(lockPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect lock path %s: %w", lockPath, err)
	}
	return os.SameFile(lockedInfo, pathInfo), nil
}

// Unix sentinels remain stable across calls; flock releases on process exit.
func RemoveIdleFileLockSentinels() {}
