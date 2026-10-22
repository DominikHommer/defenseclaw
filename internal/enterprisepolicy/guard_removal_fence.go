// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ForeignHookRemovalsFenceFile is a permanent, guardian-owned lock file.
// The guardian may replace the removal ledger, but never this file: locking
// the ledger itself would leave a reader and writer on different inodes.
// Online exchanges hold it shared through their decision and allow response
// write; a guardian ledger commit holds it exclusively.
const ForeignHookRemovalsFenceFile = "foreign-hook-removals.lock"

// ForeignHookRemovalsTurnstileFile is the fence's second permanent,
// guardian-owned lock file. A guardian commit holds it exclusively from
// before it waits for the fence until the commit is done. An exchange holds
// it shared only for the moment it takes the fence, so a pending commit
// admits no new exchange and takes the fence as soon as the exchanges
// already holding it finish their bounded response writes. Without it,
// exchanges that overlap without a gap (of any identities, from the gateway
// or any other process) would keep the fence shared and starve the commit.
const ForeignHookRemovalsTurnstileFile = "foreign-hook-removals-turnstile.lock"

// An exchange polls a held lock every foreignHookRemovalExchangePoll, a
// guardian commit every foreignHookRemovalCommitPoll.
const (
	foreignHookRemovalExchangePoll = 5 * time.Millisecond
	foreignHookRemovalCommitPoll   = time.Millisecond
)

// ForeignHookRemovalFenceFiles names the lock files the guardian creates and
// both sides check before they lock.
func ForeignHookRemovalFenceFiles() []string {
	return []string{ForeignHookRemovalsFenceFile, ForeignHookRemovalsTurnstileFile}
}

// LockForeignHookRemovalsExchange holds the fence shared through an online
// exchange's decision and allow response write. Exchanges of every identity
// hold it together; only a guardian commit excludes them. It waits, within
// ctx, while a commit holds or waits for the fence. Both users open the
// protected files for reading only; the gateway needs no write permission in
// the guardian's directory. The caller checks the files' trusted ownership
// and permissions before calling this function.
func LockForeignHookRemovalsExchange(ctx context.Context, dir string) (func(), error) {
	turnstile, fence, err := openForeignHookRemovalLocks(dir)
	if err != nil {
		return nil, err
	}
	defer turnstile.close()
	if err := turnstile.lock(ctx, false); err != nil {
		fence.close()
		return nil, err
	}
	err = fence.lock(ctx, false)
	turnstile.unlock()
	if err != nil {
		fence.close()
		return nil, err
	}
	return sync.OnceFunc(fence.release), nil
}

// LockForeignHookRemovalsCommit holds the fence exclusively through a
// guardian ledger commit. It takes the turnstile first, which stops new
// exchanges from taking the fence, then waits for the exchanges that hold
// it.
func LockForeignHookRemovalsCommit(ctx context.Context, dir string) (func(), error) {
	turnstile, fence, err := openForeignHookRemovalLocks(dir)
	if err != nil {
		return nil, err
	}
	if err := turnstile.lock(ctx, true); err != nil {
		turnstile.close()
		fence.close()
		return nil, err
	}
	if err := fence.lock(ctx, true); err != nil {
		turnstile.release()
		fence.close()
		return nil, err
	}
	return sync.OnceFunc(func() {
		fence.release()
		turnstile.release()
	}), nil
}

type foreignHookRemovalLock struct {
	path string
	info fs.FileInfo
	file *os.File
}

func openForeignHookRemovalLocks(dir string) (turnstile, fence *foreignHookRemovalLock, err error) {
	turnstile, err = openForeignHookRemovalLock(filepath.Join(dir, ForeignHookRemovalsTurnstileFile))
	if err != nil {
		return nil, nil, err
	}
	fence, err = openForeignHookRemovalLock(filepath.Join(dir, ForeignHookRemovalsFenceFile))
	if err != nil {
		turnstile.close()
		return nil, nil, err
	}
	return turnstile, fence, nil
}

func openForeignHookRemovalLock(path string) (*foreignHookRemovalLock, error) {
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
	return &foreignHookRemovalLock{path: path, info: info, file: file}, nil
}

// lock takes the file lock within ctx and checks that the path still names
// the locked file: a reader and a writer on different inodes would not
// exclude each other.
func (l *foreignHookRemovalLock) lock(ctx context.Context, exclusive bool) error {
	if err := lockForeignHookRemovalFile(ctx, l.file, exclusive); err != nil {
		return fmt.Errorf("lock foreign-hook removals: %w", err)
	}
	current, err := os.Lstat(l.path)
	if err != nil || !os.SameFile(l.info, current) {
		l.unlock()
		return fmt.Errorf("foreign-hook removal fence %s changed while locking: %v", l.path, err)
	}
	return nil
}

func (l *foreignHookRemovalLock) unlock() { unlockForeignHookRemovalFile(l.file) }

func (l *foreignHookRemovalLock) close() { _ = l.file.Close() }

func (l *foreignHookRemovalLock) release() {
	l.unlock()
	l.close()
}
