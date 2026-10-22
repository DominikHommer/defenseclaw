// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// flockRelay keeps a file flocked shared without a gap from read-only
// opens, as exchanges that overlap do, or any process that can read the
// file: each open takes the lock before the previous one lets go.
func flockRelay(t *testing.T, path string) {
	t.Helper()
	open := func() *os.File {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH); err != nil {
			t.Fatal(err)
		}
		return file
	}
	previous := open()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				_ = previous.Close()
				return
			default:
			}
			next, err := os.Open(path)
			if err == nil {
				err = syscall.Flock(int(next.Fd()), syscall.LOCK_SH)
			}
			if err != nil {
				t.Error(err)
				_ = previous.Close()
				return
			}
			time.Sleep(time.Millisecond)
			_ = previous.Close()
			previous = next
		}
	}()
	t.Cleanup(func() {
		close(stop)
		wg.Wait()
	})
}

// A read-only flock relay on every lock file the gateway can read never
// keeps the guardian's removal out of the ledger, and holds the guardian
// for a bounded time only.
func TestGuardianRemovalCommitIsNotHeldOffByAReadOnlyFlockRelay(t *testing.T) {
	guardianDir := setupForeignHookRemovalGuardian(t)
	previousWait := foreignHookRemovalLedgerLockWait
	foreignHookRemovalLedgerLockWait = 200 * time.Millisecond
	t.Cleanup(func() { foreignHookRemovalLedgerLockWait = previousWait })
	for _, name := range enterprisepolicy.ForeignHookRemovalFenceFiles() {
		flockRelay(t, filepath.Join(guardianDir, name))
	}
	time.Sleep(20 * time.Millisecond)
	done := recordAliceForeignHookRemoval()
	waitForAliceForeignHookRemoval(t, guardianDir, time.Second)
	select {
	case <-done:
	case <-time.After(foreignHookRemovalLedgerLockWait + enterprisepolicy.ForeignHookRemovalDrainWait + 2*time.Second):
		t.Fatal("a read-only flock relay held the guardian's removal commit off")
	}
}
