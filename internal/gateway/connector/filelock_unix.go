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
	"fmt"
	"os"
	"syscall"
)

// withFileLock acquires an exclusive advisory lock on path+".lock" before
// running fn, and releases it when fn returns. The sentinel stays at the
// same pathname so a waiting writer never locks an unlinked inode.
func withFileLock(path string, fn func() error) error {
	return withFileLockMode(path, false, fn)
}

func withFileLockMode(path string, _ bool, fn func() error) error {
	lockPath := path + ".lock"
	// Earlier releases unlinked the sentinel after unlocking. A contender
	// can open that old inode before it is unlinked and acquire its flock
	// afterward. Confirm the pathname still names our locked inode before
	// entering the critical section; otherwise reopen and retry.
	for attempt := 0; attempt < 8; attempt++ {
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("open lock file %s: %w", lockPath, err)
		}
		if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
			_ = lockFile.Close()
			return fmt.Errorf("acquire lock %s: %w", lockPath, err)
		}
		lockedInfo, fdErr := lockFile.Stat()
		pathInfo, pathErr := os.Stat(lockPath)
		if fdErr == nil && pathErr == nil && os.SameFile(lockedInfo, pathInfo) {
			defer func() {
				_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
				_ = lockFile.Close()
			}()
			return fn()
		}
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
		if fdErr != nil {
			return fmt.Errorf("inspect lock file %s: %w", lockPath, fdErr)
		}
		if pathErr != nil && !os.IsNotExist(pathErr) {
			return fmt.Errorf("inspect lock path %s: %w", lockPath, pathErr)
		}
	}
	return fmt.Errorf("lock path %s changed while acquiring; retry the operation", lockPath)
}

// Unix sentinels remain stable across calls; flock releases on process exit.
func RemoveIdleFileLockSentinels() {}
