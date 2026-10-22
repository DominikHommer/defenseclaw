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

//go:build windows

package enterprisestatus

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func openChangeFile(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag, 0o600)
}

// tryLockChangeFile locks byte 0 for length 1 without waiting; locked is
// false while another handle holds it.
func tryLockChangeFile(f *os.File) (locked bool, err error) {
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return false, nil
	}
	return false, err
}

func unlockChangeFile(f *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}

// inspectChangeTarget is the identity of the file at path, without
// following a reparse point: absent, or its volume serial and file index.
func inspectChangeTarget(path string) (changeTarget, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return changeTarget{}, err
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return changeTarget{Path: path}, nil
	}
	if err != nil {
		return changeTarget{}, err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return changeTarget{}, err
	}
	return changeTarget{Path: path, Present: true, Device: uint64(info.VolumeSerialNumber),
		File: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)}, nil
}
