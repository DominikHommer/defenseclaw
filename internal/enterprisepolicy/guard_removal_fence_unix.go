// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

// lockForeignHookRemovalFile takes a shared or exclusive flock. A guardian
// commit (exclusive) polls more often than an exchange, so it takes the
// turnstile between two exchanges' brief shared holds.
func lockForeignHookRemovalFile(ctx context.Context, file *os.File, exclusive bool) error {
	how, poll := syscall.LOCK_SH, foreignHookRemovalExchangePoll
	if exclusive {
		how, poll = syscall.LOCK_EX, foreignHookRemovalCommitPoll
	}
	for {
		err := syscall.Flock(int(file.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
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
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
