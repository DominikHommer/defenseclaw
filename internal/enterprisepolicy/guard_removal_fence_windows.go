// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// lockForeignHookRemovalFile takes a shared or exclusive lock on the file's
// first byte. Locks of different handles exclude each other, as flocks of
// different opens do. A guardian commit (exclusive) polls more often than an
// exchange, so it takes the turnstile between two exchanges' brief shared
// holds.
func lockForeignHookRemovalFile(ctx context.Context, file *os.File, exclusive bool) error {
	flags, poll := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY), foreignHookRemovalExchangePoll
	if exclusive {
		flags, poll = flags|windows.LOCKFILE_EXCLUSIVE_LOCK, foreignHookRemovalCommitPoll
	}
	for {
		var overlapped windows.Overlapped
		err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &overlapped)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

func unlockForeignHookRemovalFile(file *os.File) {
	var overlapped windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}
