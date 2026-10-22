// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"context"
	"errors"
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
// write. A guardian holds it exclusively only for the moment it takes to
// see that the exchanges that may have read the previous ledger are done.
const ForeignHookRemovalsFenceFile = "foreign-hook-removals.lock"

// ForeignHookRemovalsLedgerLockFile is the guardian's second permanent lock
// file. It serializes ledger commits, from every guardian process, through
// their read and publish only: a guardian releases it before it waits for
// exchanges, so one account's wait never delays another account's
// publication. Exchanges never take it, so it never delays one.
const ForeignHookRemovalsLedgerLockFile = "foreign-hook-removals-ledger.lock"

// ForeignHookRemovalExchangeHold bounds an online exchange's allow: an
// exchange answers allow only within this time after it took the fence,
// and refuses or cuts the answer after it. ForeignHookRemovalDrainWait is
// the longest a guardian waits, after it published a ledger, for the
// exchanges that may have read the previous one: past it, every such
// exchange has answered or has been cut, whatever holds the fence.
const (
	ForeignHookRemovalExchangeHold = time.Second
	ForeignHookRemovalDrainWait    = ForeignHookRemovalExchangeHold + 500*time.Millisecond
)

// An exchange polls a held lock every foreignHookRemovalExchangePoll, a
// guardian every foreignHookRemovalGuardianPoll.
const (
	foreignHookRemovalExchangePoll = 5 * time.Millisecond
	foreignHookRemovalGuardianPoll = time.Millisecond
)

// ForeignHookRemovalFenceFiles names the lock files the guardian creates.
// Each must stay an empty regular file; both sides refuse one that is not.
func ForeignHookRemovalFenceFiles() []string {
	return []string{ForeignHookRemovalsFenceFile, ForeignHookRemovalsLedgerLockFile}
}

// LockForeignHookRemovalsExchange holds the fence shared through an online
// exchange's decision and allow response write. Exchanges of every identity
// hold it together. It waits, within ctx, only while a guardian holds the
// fence for its brief exclusive check. The gateway opens the file for
// reading only; it needs no write permission in the guardian's directory.
// The caller checks the file's trusted ownership and permissions before
// calling this function.
func LockForeignHookRemovalsExchange(ctx context.Context, dir string) (func(), error) {
	return lockForeignHookRemovalPath(ctx, filepath.Join(dir, ForeignHookRemovalsFenceFile), false)
}

// LockForeignHookRemovalsDrain holds the fence exclusively. It succeeds only
// when no exchange holds it, so a guardian that takes it after publishing a
// ledger knows that every exchange that may have read the previous ledger
// is done. The guardian releases it at once (AwaitForeignHookRemovalExchanges).
func LockForeignHookRemovalsDrain(ctx context.Context, dir string) (func(), error) {
	return lockForeignHookRemovalPath(ctx, filepath.Join(dir, ForeignHookRemovalsFenceFile), true)
}

// LockForeignHookRemovalsLedger holds the guardian's ledger lock through one
// commit's read and publish, so commits of different guardian processes do
// not lose each other's removals. The guardian releases it before
// AwaitForeignHookRemovalExchanges.
func LockForeignHookRemovalsLedger(ctx context.Context, dir string) (func(), error) {
	return lockForeignHookRemovalPath(ctx, filepath.Join(dir, ForeignHookRemovalsLedgerLockFile), true)
}

// AwaitForeignHookRemovalExchanges runs after the guardian published a new
// removal ledger. Exchanges that start after the publication read the new
// ledger, so it waits only for those that may have read the previous one:
// it returns drained once it takes the fence exclusively (it releases it at
// once), or after ForeignHookRemovalDrainWait, by when each of them has
// answered or been cut at its ForeignHookRemovalExchangeHold deadline.
// Exchanges that keep the fence shared without a gap therefore delay the
// guardian by a bounded time, and never past the publication. A fence that
// cannot be locked is an error, returned after the same wait.
func AwaitForeignHookRemovalExchanges(dir string) (drained bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), ForeignHookRemovalDrainWait)
	defer cancel()
	unlock, err := LockForeignHookRemovalsDrain(ctx, dir)
	if err == nil {
		unlock()
		return true, nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return false, nil
	}
	<-ctx.Done()
	return false, err
}

func lockForeignHookRemovalPath(ctx context.Context, path string, exclusive bool) (func(), error) {
	lock, err := openForeignHookRemovalLock(path)
	if err != nil {
		return nil, err
	}
	if err := lock.lock(ctx, exclusive); err != nil {
		lock.close()
		return nil, err
	}
	return sync.OnceFunc(lock.release), nil
}

type foreignHookRemovalLock struct {
	path string
	info fs.FileInfo
	file *os.File
}

// openForeignHookRemovalLock opens an empty regular lock file. A lock file
// with content is not one the guardian made: both sides refuse it, as they
// refuse a missing or replaced one.
func openForeignHookRemovalLock(path string) (*foreignHookRemovalLock, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect foreign-hook removal fence: %w", err)
	}
	if err := checkForeignHookRemovalLockInfo(path, info); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open foreign-hook removal fence: %w", err)
	}
	opened, err := file.Stat()
	if err == nil && (!os.SameFile(info, opened) || opened.Size() != 0) {
		err = errors.New("not the empty file inspected")
	}
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("foreign-hook removal fence %s changed while opening: %v", path, err)
	}
	return &foreignHookRemovalLock{path: path, info: info, file: file}, nil
}

func checkForeignHookRemovalLockInfo(path string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() || info.Size() != 0 {
		return fmt.Errorf("foreign-hook removal fence %s is not an empty regular file", path)
	}
	return nil
}

// lock takes the file lock within ctx and checks that the path still names
// the locked, empty file: a reader and a writer on different inodes would
// not exclude each other.
func (l *foreignHookRemovalLock) lock(ctx context.Context, exclusive bool) error {
	poll := foreignHookRemovalExchangePoll
	if exclusive {
		poll = foreignHookRemovalGuardianPoll
	}
	if err := lockForeignHookRemovalFile(ctx, l.file, exclusive, poll); err != nil {
		return fmt.Errorf("lock foreign-hook removals: %w", err)
	}
	current, err := os.Lstat(l.path)
	if err == nil && !os.SameFile(l.info, current) {
		err = errors.New("replaced")
	}
	if err == nil {
		err = checkForeignHookRemovalLockInfo(l.path, current)
	}
	if err != nil {
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
