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

// until 1.1: the stub is written into a script file only when it and its
// hooks folder have one owner, so a name that leads to another account's
// marked file (a root-owned managed hook) is never written by a privileged
// teardown.
func TestRemovedInPlaceOnlyForTheFolderOwnersFile(t *testing.T) {
	user := removedFakeInfo{&syscall.Stat_t{Uid: 1001}}
	root := removedFakeInfo{&syscall.Stat_t{Uid: 0}}
	if err := removedInPlaceRefusal(user, user); err != nil {
		t.Fatalf("the folder owner's own file is refused: %v", err)
	}
	if removedInPlaceRefusal(root, user) == nil || removedInPlaceRefusal(user, root) == nil {
		t.Fatal("a file of another owner than its folder's is written in place")
	}
	if removedInPlaceRefusal(removedFakeInfo{}, user) == nil || removedInPlaceRefusal(user, removedFakeInfo{}) == nil {
		t.Fatal("an owner that cannot be read allows an in-place write")
	}
	info, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := removedInPlaceRefusal(info, info); err != nil {
		t.Fatalf("a real file of this account is refused: %v", err)
	}
}
