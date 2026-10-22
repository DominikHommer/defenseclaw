// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"
)

type removedFakeInfo struct{ stat any }

func (removedFakeInfo) Name() string       { return "f" }
func (removedFakeInfo) Size() int64        { return 0 }
func (removedFakeInfo) Mode() fs.FileMode  { return 0o600 }
func (removedFakeInfo) ModTime() time.Time { return time.Time{} }
func (removedFakeInfo) IsDir() bool        { return false }
func (i removedFakeInfo) Sys() any         { return i.stat }

// until 1.1: a hard-linked script is written in place only when it and its
// hooks folder have one owner, so a link to another account's marked file
// (a root-owned managed hook) is never written by a privileged teardown.
func TestRemovedMayWriteInPlaceOnlyForTheFolderOwnersFile(t *testing.T) {
	user := removedFakeInfo{&syscall.Stat_t{Uid: 1001}}
	root := removedFakeInfo{&syscall.Stat_t{Uid: 0}}
	if !removedMayWriteInPlace(user, user) {
		t.Fatal("the folder owner's own file is not written in place")
	}
	if removedMayWriteInPlace(root, user) || removedMayWriteInPlace(user, root) {
		t.Fatal("a file of another owner than its folder's is written in place")
	}
	if removedMayWriteInPlace(removedFakeInfo{}, user) || removedMayWriteInPlace(user, removedFakeInfo{}) {
		t.Fatal("an owner that cannot be read allows an in-place write")
	}
	info, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !removedMayWriteInPlace(info, info) {
		t.Fatal("a real file of this account is not written in place")
	}
}
