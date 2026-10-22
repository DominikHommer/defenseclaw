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
// response never refuses another account's exchange; a guardian's drain
// check still waits for every one of them.
func TestForeignHookRemovalExchangesShareTheFenceADrainExcludes(t *testing.T) {
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
		if unlock, err := tryForeignHookRemovalLock(LockForeignHookRemovalsDrain, dir, 50*time.Millisecond); err == nil {
			unlock()
			t.Fatalf("a drain check overtook %d exchanges that hold the fence", 3-i)
		}
		release()
		release() // releasing twice is harmless
	}
	drain, err := tryForeignHookRemovalLock(LockForeignHookRemovalsDrain, dir, time.Second)
	if err != nil {
		t.Fatalf("the drain check did not take the free fence: %v", err)
	}
	if unlock, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, 50*time.Millisecond); err == nil {
		unlock()
		drain()
		t.Fatal("an exchange took the fence during a drain check")
	}
	drain()
	exchange, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, time.Second)
	if err != nil {
		t.Fatalf("an exchange after the drain check: %v", err)
	}
	exchange()
}

// relayForeignHookRemovalFence keeps the fence shared without a gap, as
// exchanges that overlap do, or as a read-only process that relays flocks
// between two open files: each holder takes the lock before the previous
// one lets go.
func relayForeignHookRemovalFence(t *testing.T, dir string) (served *atomic.Int64) {
	t.Helper()
	served = new(atomic.Int64)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	path := filepath.Join(dir, ForeignHookRemovalsFenceFile)
	held := make(chan struct{}, 1)
	held <- struct{}{}
	previous, err := openForeignHookRemovalLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := previous.lock(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				previous.release()
				return
			default:
			}
			next, err := openForeignHookRemovalLock(path)
			if err != nil {
				t.Error(err)
				previous.release()
				return
			}
			if err := next.lock(context.Background(), false); err != nil {
				t.Error(err)
				next.close()
				previous.release()
				return
			}
			time.Sleep(2 * time.Millisecond)
			previous.release()
			previous = next
			served.Add(1)
		}
	}()
	t.Cleanup(func() {
		close(stop)
		wg.Wait()
	})
	return served
}

type foreignHookRemovalAwaitResult struct {
	drained bool
	err     error
}

func awaitForeignHookRemovalExchanges(dir string) <-chan foreignHookRemovalAwaitResult {
	result := make(chan foreignHookRemovalAwaitResult, 1)
	go func() {
		drained, err := AwaitForeignHookRemovalExchanges(dir)
		result <- foreignHookRemovalAwaitResult{drained, err}
	}()
	return result
}

// A guardian that published a removal is never held off by exchanges that
// keep the fence shared without a gap: it waits at most
// ForeignHookRemovalDrainWait, by when each exchange that may have read the
// previous ledger has answered or been cut. New exchanges take the fence at
// once all the while.
func TestForeignHookRemovalAwaitIsBoundedUnderContinuousExchanges(t *testing.T) {
	dir := writeForeignHookRemovalFenceFiles(t)
	served := relayForeignHookRemovalFence(t, dir)
	for served.Load() < 10 {
		time.Sleep(time.Millisecond)
	}
	started := time.Now()
	awaited := awaitForeignHookRemovalExchanges(dir)
	for i := 0; i < 5; i++ {
		unlock, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, 50*time.Millisecond)
		if err != nil {
			t.Fatalf("an exchange waited while a guardian awaited the exchanges: %v", err)
		}
		unlock()
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case result := <-awaited:
		if result.err != nil || result.drained {
			t.Fatalf("the guardian's wait under continuous exchanges: drained %v, %v", result.drained, result.err)
		}
		if elapsed := time.Since(started); elapsed < ForeignHookRemovalDrainWait-50*time.Millisecond {
			t.Fatalf("the guardian stopped waiting after %v, before every exchange that may have read the previous ledger was bound to have answered", elapsed)
		}
	case <-time.After(ForeignHookRemovalDrainWait + 2*time.Second):
		t.Fatal("continuous exchanges held the guardian off past the drain wait")
	}
}

// With the exchanges that held the fence done, the guardian goes on at once.
func TestForeignHookRemovalAwaitReturnsWhenTheExchangesFinish(t *testing.T) {
	dir := writeForeignHookRemovalFenceFiles(t)
	held, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	awaited := awaitForeignHookRemovalExchanges(dir)
	select {
	case <-awaited:
		held()
		t.Fatal("the guardian went on while an exchange held the fence")
	case <-time.After(50 * time.Millisecond):
	}
	held()
	select {
	case result := <-awaited:
		if result.err != nil || !result.drained || time.Since(started) >= ForeignHookRemovalDrainWait {
			t.Fatalf("drained = %v, %v after %v", result.drained, result.err, time.Since(started))
		}
	case <-time.After(ForeignHookRemovalDrainWait):
		t.Fatal("the guardian did not go on once the exchange finished")
	}
}

// The ledger lock serializes guardian commits and nothing else: exchanges
// and drain checks never wait on it.
func TestForeignHookRemovalLedgerLockSerializesGuardiansOnly(t *testing.T) {
	dir := writeForeignHookRemovalFenceFiles(t)
	ledger, err := tryForeignHookRemovalLock(LockForeignHookRemovalsLedger, dir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger()
	if unlock, err := tryForeignHookRemovalLock(LockForeignHookRemovalsLedger, dir, 50*time.Millisecond); err == nil {
		unlock()
		t.Fatal("two guardian commits held the ledger lock together")
	}
	exchange, err := tryForeignHookRemovalLock(LockForeignHookRemovalsExchange, dir, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("an exchange waited on the ledger lock: %v", err)
	}
	exchange()
	drain, err := tryForeignHookRemovalLock(LockForeignHookRemovalsDrain, dir, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("a drain check waited on the ledger lock: %v", err)
	}
	drain()
}

// Any doubt about a lock file refuses its locks: a missing or replaced one,
// one that is not a regular file, or one with content.
func TestForeignHookRemovalFenceRefusesMissingReplacedOrNonEmptyFiles(t *testing.T) {
	locks := map[string][]func(context.Context, string) (func(), error){
		ForeignHookRemovalsFenceFile:      {LockForeignHookRemovalsExchange, LockForeignHookRemovalsDrain},
		ForeignHookRemovalsLedgerLockFile: {LockForeignHookRemovalsLedger},
	}
	if len(locks) != len(ForeignHookRemovalFenceFiles()) {
		t.Fatal("a lock file has no lock under test")
	}
	for _, name := range ForeignHookRemovalFenceFiles() {
		t.Run(name, func(t *testing.T) {
			dir := writeForeignHookRemovalFenceFiles(t)
			path := filepath.Join(dir, name)
			refused := func(state string) {
				t.Helper()
				for _, lock := range locks[name] {
					if unlock, err := tryForeignHookRemovalLock(lock, dir, 50*time.Millisecond); err == nil {
						unlock()
						t.Fatalf("locked %s", state)
					}
				}
			}
			if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
				t.Fatal(err)
			}
			refused("a lock file with content")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			refused("without the lock file")
			if err := os.Mkdir(path, 0o750); err != nil {
				t.Fatal(err)
			}
			refused("a directory")
		})
	}
	// An unusable fence is an error for the guardian, after the full wait:
	// an exchange that opened the fence before it went bad is still bound by
	// its hold.
	dir := writeForeignHookRemovalFenceFiles(t)
	if err := os.WriteFile(filepath.Join(dir, ForeignHookRemovalsFenceFile), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if drained, err := AwaitForeignHookRemovalExchanges(dir); err == nil || drained {
		t.Fatalf("awaited an unusable fence: drained %v, %v", drained, err)
	}
	if elapsed := time.Since(started); elapsed < ForeignHookRemovalDrainWait-50*time.Millisecond {
		t.Fatalf("the guardian stopped waiting on an unusable fence after %v", elapsed)
	}
}

// A lock file that gains content after an exchange opened it is refused
// when the exchange locks it.
func TestForeignHookRemovalFenceRefusesALockFileThatGainedContent(t *testing.T) {
	dir := writeForeignHookRemovalFenceFiles(t)
	path := filepath.Join(dir, ForeignHookRemovalsFenceFile)
	lock, err := openForeignHookRemovalLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.close()
	if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := lock.lock(context.Background(), false); err == nil {
		lock.unlock()
		t.Fatal("locked a fence that gained content")
	}
}
