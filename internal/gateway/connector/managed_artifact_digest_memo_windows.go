//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The three are replaced in tests.
var (
	managedArtifactDigestMemoEligible = managedEnterpriseHookBinaryPath
	openManagedArtifactExclusive      = openWindowsManagedArtifactExclusive
	managedArtifactStampOf            = windowsManagedArtifactStamp
)

// managedEnterpriseHookBinaryPath reports whether path is the hook binary of
// this managed enterprise deployment (managedEnterpriseWindowsHookBinary):
// an administrator-owned file that no untrusted account can write, on a
// fixed NTFS volume. Per-user files, agent executables and repository
// builds are never memoized.
func managedEnterpriseHookBinaryPath(path string) bool {
	executable, err := os.Executable()
	if err != nil {
		return false
	}
	hook := managedEnterpriseWindowsHookBinary(executable)
	return hook != "" && strings.EqualFold(filepath.Clean(hook), filepath.Clean(path))
}

// openWindowsManagedArtifactExclusive opens path for reading with a share
// mode that admits other readers and a rename, but no writer: it fails while
// any handle may write the file, and while it is open no handle can. It does
// not follow a reparse point at the leaf.
func openWindowsManagedArtifactExclusive(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

// windowsManagedArtifactFileBasicInfo is FILE_BASIC_INFO.
type windowsManagedArtifactFileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

// windowsManagedArtifactStamp takes the stamp of the open file. ok is false
// when a value cannot be read or the volume keeps no change journal: an
// account that may write the file can set every time stamp back, but not the
// journal number, which every write changes. The caller then reads the file
// in full and memoizes nothing.
func windowsManagedArtifactStamp(file *os.File) (managedArtifactStamp, bool) {
	handle := windows.Handle(file.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return managedArtifactStamp{}, false
	}
	var basic windowsManagedArtifactFileBasicInfo
	if err := windows.GetFileInformationByHandleEx(
		handle,
		windows.FileBasicInfo,
		(*byte)(unsafe.Pointer(&basic)),
		uint32(unsafe.Sizeof(basic)),
	); err != nil {
		return managedArtifactStamp{}, false
	}
	usn := windowsManagedArtifactUSN(handle)
	if usn == 0 {
		return managedArtifactStamp{}, false
	}
	return managedArtifactStamp{
		Volume:     info.VolumeSerialNumber,
		ID:         uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
		Size:       int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow),
		Links:      info.NumberOfLinks,
		Written:    basic.LastWriteTime,
		Changed:    basic.ChangeTime,
		USN:        usn,
		Attributes: basic.FileAttributes,
	}, true
}

// windowsManagedArtifactUSN is the update sequence number the change journal
// of the volume last recorded for the open file, or 0 without a journal.
func windowsManagedArtifactUSN(handle windows.Handle) int64 {
	var record [128]uint64 // USN_RECORD_V2 or V3 with a name of up to 255 characters
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(&record[0])), len(record)*8)
	var returned uint32
	if err := windows.DeviceIoControl(
		handle,
		windows.FSCTL_READ_FILE_USN_DATA,
		nil,
		0,
		&buffer[0],
		uint32(len(buffer)),
		&returned,
		nil,
	); err != nil || returned < 8 {
		return 0
	}
	// The record starts with its length (4 bytes) and major version (2).
	switch binary.LittleEndian.Uint16(buffer[4:6]) {
	case 2: // 64-bit file references
		if returned >= 32 {
			return int64(binary.LittleEndian.Uint64(buffer[24:32]))
		}
	case 3: // 128-bit file references
		if returned >= 48 {
			return int64(binary.LittleEndian.Uint64(buffer[40:48]))
		}
	}
	return 0
}
