// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writeForeignHookRemovalFenceFiles(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range ForeignHookRemovalFenceFiles() {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func tryForeignHookRemovalLock(lock func(context.Context, string) (func(), error), dir string, wait time.Duration) (func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return lock(ctx, dir)
}

// Exchanges of different identities hold the fence together, so one slow
// response never refuses another account's exchange; a guardian commit
// still waits for every one of them.
func TestForeignHookRemovalExchangesShareTheFenceACommitExcludes(t *testing.T) {
	dir := writeForeignHookRemovalFenceFiles(t)
	first, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	second, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, 100*time.Millisecond)
	if err != nil {
		first()
		t.Fatalf("a second exchange waited on the first: %v", err)
	}
	third, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, 100*time.Millisecond)
	if err != nil {
		first()
		second()
		t.Fatalf("a third exchange waited on the first two: %v", err)
	}
	for i, release := range []func(){first, second, third} {
		if unlock, err := tryForeignHookRemovalLock(LockForeignHookRemovalsCommit, dir, 50*time.Millisecond); err == nil {
			unlock()
			t.Fatalf("a commit overtook %d exchanges that hold the fence", 3-i)
		}
		release()
		release() // releasing twice is harmless
	}
	commit, err := tryForeignHookRemovalLock(LockForeignHookRemovalsCommit, dir, time.Second)
	if err != nil {
		t.Fatalf("the commit did not take the free fence: %v", err)
	}
	if unlock, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, 50*time.Millisecond); err == nil {
		unlock()
		commit()
		t.Fatal("an exchange took the fence during a commit")
	}
	if unlock, err := tryForeignHookRemovalLock(LockForeignHookRemovalsCommit, dir, 50*time.Millisecond); err == nil {
		unlock()
		commit()
		t.Fatal("two commits held the fence together")
	}
	commit()
	exchange, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, time.Second)
	if err != nil {
		t.Fatalf("an exchange after the commit: %v", err)
	}
	exchange()
}

// A commit that waits for an exchange admits no new exchange: otherwise
// exchanges that overlap without a gap would keep the fence shared forever.
func TestForeignHookRemovalPendingCommitAdmitsNoNewExchange(t *testing.T) {
	dir := writeForeignHookRemovalFenceFiles(t)
	held, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	committed := make(chan func(), 1)
	go func() {
		unlock, err := LockForeignHookRemovalsCommit(context.Background(), dir)
		if err != nil {
			t.Error(err)
			close(committed)
			return
		}
		committed <- unlock
	}()
	// Wait until the commit is pending: it holds the turnstile.
	deadline := time.Now().Add(3 * time.Second)
	for {
		probe, err := openForeignHookRemovalLock(filepath.Join(dir, ForeignHookRemovalsTurnstileFile))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		err = probe.lock(ctx, false)
		cancel()
		if err != nil {
			probe.close()
			break
		}
		probe.release()
		if time.Now().After(deadline) {
			held()
			t.Fatal("the commit never became pending")
		}
		time.Sleep(time.Millisecond)
	}
	if unlock, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, 100*time.Millisecond); err == nil {
		unlock()
		held()
		t.Fatal("a new exchange took the fence ahead of a pending commit")
	}
	held()
	select {
	case unlock, ok := <-committed:
		if !ok {
			t.Fatal("commit failed")
		}
		unlock()
	case <-time.After(3 * time.Second):
		t.Fatal("the commit did not take the fence once the exchange finished")
	}
}

// A guardian commit lands under sustained online exchanges, of the gateway
// or of any other process, that overlap so the fence is never free, and no
// exchange holds the fence while the commit does.
func TestForeignHookRemovalCommitLandsUnderSustainedExchanges(t *testing.T) {
	dir := writeForeignHookRemovalFenceFiles(t)
	var holders, served atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 5 * time.Millisecond)
			for {
				select {
				case <-stop:
					return
				default:
				}
				unlock, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, 500*time.Millisecond)
				if err != nil {
					continue
				}
				holders.Add(1)
				served.Add(1)
				time.Sleep(20 * time.Millisecond)
				holders.Add(-1)
				unlock()
			}
		}(i)
	}
	defer func() {
		close(stop)
		wg.Wait()
	}()
	for served.Load() < 8 {
		time.Sleep(time.Millisecond)
	}
	for round := 0; round < 3; round++ {
		started := time.Now()
		unlock, err := tryForeignHookRemovalLock(LockForeignHookRemovalsCommit, dir, 3*time.Second)
		if err != nil {
			t.Fatalf("commit %d starved by sustained exchanges: %v", round, err)
		}
		if n := holders.Load(); n != 0 {
			unlock()
			t.Fatalf("commit %d holds the fence with %d exchanges", round, n)
		}
		time.Sleep(10 * time.Millisecond)
		if n := holders.Load(); n != 0 {
			unlock()
			t.Fatalf("an exchange took the fence during commit %d", round)
		}
		unlock()
		t.Logf("commit %d took %v", round, time.Since(started))
		before := served.Load()
		for served.Load() < before+4 {
			time.Sleep(time.Millisecond)
		}
	}
}

// Any doubt about the fence refuses the lock: a missing or replaced lock
// file, or one that is not a regular file.
func TestForeignHookRemovalFenceRefusesMissingOrReplacedFiles(t *testing.T) {
	for _, name := range ForeignHookRemovalFenceFiles() {
		t.Run(name, func(t *testing.T) {
			dir := writeForeignHookRemovalFenceFiles(t)
			path := filepath.Join(dir, name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			for _, lock := range []func(context.Context, string) (func(), error){LockForeignHookRemovalsExchange, LockForeignHookRemovalsCommit} {
				if unlock, err := tryForeignHookRemovalLock(lock, dir, 50*time.Millisecond); err == nil {
					unlock()
					t.Fatal("locked without the lock file")
				}
			}
			if err := os.Mkdir(path, 0o750); err != nil {
				t.Fatal(err)
			}
			for _, lock := range []func(context.Context, string) (func(), error){LockForeignHookRemovalsExchange, LockForeignHookRemovalsCommit} {
				if unlock, err := tryForeignHookRemovalLock(lock, dir, 50*time.Millisecond); err == nil {
					unlock()
					t.Fatal("locked a directory")
				}
			}
		})
	}
}
