// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"context"
	"fmt"
	"os"
)

// ForeignHookRemovalsFenceFile is a permanent, guardian-owned lock file.
// The guardian may replace the removal ledger, but never this file: locking
// the ledger itself would leave a reader and writer on different inodes.
const ForeignHookRemovalsFenceFile = "foreign-hook-removals.lock"

// ForeignHookCleanupFenceFile also covers the interval from the first hook
// removal through the ledger commit. A reader that saw the old ledger must
// finish its allow response before cleanup can remove a hook.
const ForeignHookCleanupFenceFile = "foreign-hook-cleanup.lock"

// LockForeignHookRemovals holds one interprocess fence through a ledger
// commit or an online decision's response write. Both users open this
// protected file for reading; the gateway needs no write permission in the
// guardian's directory. The caller checks the file's trusted ownership and
// permissions before calling this function.
func LockForeignHookRemovals(ctx context.Context, path string) (func(), error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect foreign-hook removal fence: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("foreign-hook removal fence %s is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open foreign-hook removal fence: %w", err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("foreign-hook removal fence %s changed while opening: %v", path, err)
	}
	if err := lockForeignHookRemovalFile(ctx, file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock foreign-hook removals: %w", err)
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		unlockForeignHookRemovalFile(file)
		_ = file.Close()
		return nil, fmt.Errorf("foreign-hook removal fence %s changed while locking: %v", path, err)
	}
	return func() {
		unlockForeignHookRemovalFile(file)
		_ = file.Close()
	}, nil
}
