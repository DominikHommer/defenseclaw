// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// openNativeStateFile opens native state for reading with read, write and
// delete sharing. os.Open omits FILE_SHARE_DELETE, so it fails with a sharing
// violation while a publisher holds its renamed handle on the new file, and
// it makes that publisher's atomic replacement fail while Setup reads. The
// caller binds the read to the Lstat identity before and after, so a
// replacement during the read is detected and read again.
func openNativeStateFile(path string) (*os.File, error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("wrap native state handle: %s", path)
	}
	return file, nil
}

// nativeStateFileBusy reports a transient lock: another process opened the
// file without the sharing Setup needs, or holds a byte-range lock on it.
func nativeStateFileBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

// Restart Manager names the processes that hold a file open. It is used only
// to word the error after the retry window, so every failure here means "no
// name" rather than a different error.
var (
	modRstrtmgr             = windows.NewLazySystemDLL("rstrtmgr.dll")
	procRmStartSession      = modRstrtmgr.NewProc("RmStartSession")
	procRmRegisterResources = modRstrtmgr.NewProc("RmRegisterResources")
	procRmGetList           = modRstrtmgr.NewProc("RmGetList")
	procRmEndSession        = modRstrtmgr.NewProc("RmEndSession")
)

const (
	rmSessionKeyChars = 32 // CCH_RM_SESSION_KEY
	rmMaxAppNameChars = 255
	rmMaxSvcNameChars = 63
	rmMaxHolders      = 8
)

// rmProcessInfo is RM_PROCESS_INFO.
type rmProcessInfo struct {
	ProcessID        uint32
	ProcessStartTime windows.Filetime
	AppName          [rmMaxAppNameChars + 1]uint16
	ServiceShortName [rmMaxSvcNameChars + 1]uint16
	ApplicationType  uint32
	AppStatus        uint32
	TSSessionID      uint32
	Restartable      int32
}

func nativeStateFileHolders(path string) []string {
	if procRmStartSession.Find() != nil || procRmRegisterResources.Find() != nil ||
		procRmGetList.Find() != nil || procRmEndSession.Find() != nil {
		return nil
	}
	resource, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil
	}
	var session uint32
	var key [rmSessionKeyChars + 1]uint16
	if r, _, _ := procRmStartSession.Call(
		uintptr(unsafe.Pointer(&session)), 0, uintptr(unsafe.Pointer(&key[0])),
	); r != 0 {
		return nil
	}
	defer procRmEndSession.Call(uintptr(session))

	resources := [1]*uint16{resource}
	if r, _, _ := procRmRegisterResources.Call(
		uintptr(session), 1, uintptr(unsafe.Pointer(&resources[0])), 0, 0, 0, 0,
	); r != 0 {
		return nil
	}
	var infos [rmMaxHolders]rmProcessInfo
	var needed, reasons uint32
	count := uint32(len(infos))
	r, _, _ := procRmGetList.Call(
		uintptr(session),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&infos[0])),
		uintptr(unsafe.Pointer(&reasons)),
	)
	if r == uintptr(windows.ERROR_MORE_DATA) {
		return []string{fmt.Sprintf("%d processes", needed)}
	}
	if r != 0 || count > uint32(len(infos)) {
		return nil
	}
	holders := make([]string, 0, count)
	for _, info := range infos[:count] {
		name := windows.UTF16ToString(info.AppName[:])
		if name == "" {
			name = "process"
		}
		holders = append(holders, fmt.Sprintf("%s (PID %d)", name, info.ProcessID))
	}
	return holders
}
