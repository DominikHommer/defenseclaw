// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package ideplugins

import (
	"bytes"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openedPath returns the path macOS gives the opened file (F_GETPATH).
func openedPath(f *os.File) (string, bool) {
	conn, err := f.SyscallConn()
	if err != nil {
		return "", false
	}
	var path string
	ok := false
	_ = conn.Control(func(fd uintptr) {
		var buf [unix.PathMax]byte
		if _, _, errno := unix.Syscall(unix.SYS_FCNTL, fd, unix.F_GETPATH, uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
			return
		}
		if n := bytes.IndexByte(buf[:], 0); n > 0 {
			path, ok = string(buf[:n]), true
		}
	})
	return path, ok
}
