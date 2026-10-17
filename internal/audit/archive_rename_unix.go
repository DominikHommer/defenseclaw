// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package audit

import (
	"errors"
	"io/fs"
	"os"
)

// renameNoReplace moves from to to and fails with fs.ErrExist when to exists.
// os.Rename replaces an existing file, so a name checked free a moment before
// could still be overwritten by a second start moving a store at the same
// time (rel-1-0-2:GAP-0614). A hard link claims the name atomically; the old
// name is then removed. On a file system without hard links the move falls
// back to a checked rename.
func renameNoReplace(from, to string) error {
	err := os.Link(from, to)
	if err == nil {
		if removeErr := os.Remove(from); removeErr != nil {
			_ = os.Remove(to)
			return removeErr
		}
		return nil
	}
	if errors.Is(err, fs.ErrExist) || errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if _, statErr := os.Lstat(to); statErr == nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: fs.ErrExist}
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return statErr
	}
	return os.Rename(from, to)
}
