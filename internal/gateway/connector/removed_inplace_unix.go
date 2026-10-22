// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"syscall"
)

// removedMayWriteInPlace reports whether the teardown may write the stub into
// a removed connector's hard-linked script (removed.go): only when the file
// and its hooks folder have one owner. until 1.1.
func removedMayWriteInPlace(file, folder os.FileInfo) bool {
	fileStat, ok := file.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	folderStat, ok := folder.Sys().(*syscall.Stat_t)
	return ok && fileStat.Uid == folderStat.Uid
}
