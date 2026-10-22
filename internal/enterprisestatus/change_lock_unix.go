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

package enterprisestatus

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func openChangeFile(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag|syscall.O_NOFOLLOW, 0o600)
}

// tryLockChangeFile takes flock(LOCK_EX) without blocking; locked is false
// while another open file holds it.
func tryLockChangeFile(f *os.File) (locked bool, err error) {
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return false, nil
	}
	return false, err
}

func unlockChangeFile(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

// inspectChangeTarget is the identity of the file at path, without
// following a final symlink: absent, or its device and inode.
func inspectChangeTarget(path string) (changeTarget, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return changeTarget{Path: path}, nil
	}
	if err != nil {
		return changeTarget{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return changeTarget{}, errors.New("the file system reports no file identity")
	}
	return changeTarget{Path: path, Present: true, Device: uint64(st.Dev), File: uint64(st.Ino)}, nil
}
