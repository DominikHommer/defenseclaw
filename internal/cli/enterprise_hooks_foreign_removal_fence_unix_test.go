// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
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

// The per-user workers' removals are marked when the worker ended, for
// every connector it cleaned, however long each commit then waits.
func TestStandaloneWorkerRemovalsAreMarkedWhenTheWorkerEnds(t *testing.T) {
	guardianDir := setupForeignHookRemovalGuardian(t)
	previousManifest := enterpriseHookManifest
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		enterpriseHookManifest = previousManifest
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.unrepaired = nil
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	cfg.Enterprise.MachinePolicy = config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{
		"cursor": {}, "opencode": {}, "amp": {},
	}}
	enterpriseHookManifest = filepath.Join(t.TempDir(), "targets.yaml")
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{{User: "alice", UID: 4242, GID: 4242, Home: "/home/alice", HomeInode: 7}}, nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
	}
	cleaned := make(chan struct{})
	var once sync.Once
	var connectors atomic.Int64
	enterpriseHookWorkerRunner = func(_ context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response := enterpriseHookWorkerResponse{Cleanup: map[string]enterpriseHookWorkerCleanupReport{}}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{Index: target.Index, OK: true})
		}
		for _, cleanup := range request.ForeignCleanup {
			response.Cleanup[cleanup.Connector] = enterpriseHookWorkerCleanupReport{Removed: []string{"/home/alice/." + cleanup.Connector + "/hooks.json"}}
		}
		if len(request.ForeignCleanup) > 0 {
			connectors.Store(int64(len(request.ForeignCleanup)))
			defer once.Do(func() { close(cleaned) })
		}
		return response, nil
	}
	checkRemovalMarkedAtCleanup(t, guardianDir, "4242", cleaned, func() {
		runEnterpriseHookStandaloneForeignCleanup(context.Background(), io.Discard, time.Now(), enterprisehooks.Manifest{}, nil, "")
	})
	// A later connector's commit waits for the earlier one's; its mark is
	// still the worker's end.
	if connectors.Load() < 2 {
		t.Fatalf("the worker cleaned %d connector(s); the test needs two", connectors.Load())
	}
}

// A worker's slot is free once it ends: recording its outcome, which may
// wait for exchanges, never holds off another account's worker.
func TestWorkerPoolFreesTheSlotBeforeTheOutcomeIsRecorded(t *testing.T) {
	previous := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = previous })
	var started atomic.Int64
	both := make(chan struct{})
	enterpriseHookWorkerRunner = func(context.Context, enterpriseHookWorkerAccount, enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		if started.Add(1) == 2 {
			close(both)
		}
		return enterpriseHookWorkerResponse{}, nil
	}
	jobs := []enterpriseHookWorkerJob{
		{Account: enterpriseHookWorkerAccount{UID: 1001, User: "alice", Home: "/home/alice"}},
		{Account: enterpriseHookWorkerAccount{UID: 1002, User: "bob", Home: "/home/bob"}},
	}
	var first atomic.Bool
	var heldOff atomic.Bool
	outcomes := runEnterpriseHookWorkerPoolReporting(context.Background(), jobs, 1, func(enterpriseHookWorkerOutcome) {
		if !first.CompareAndSwap(false, true) {
			return
		}
		select {
		case <-both:
		case <-time.After(2 * time.Second):
			heldOff.Store(true)
		}
	})
	if heldOff.Load() {
		t.Fatal("recording one account's outcome held off the next account's worker")
	}
	if len(outcomes) != 2 || outcomes[0].Job.Account.UID != 1001 || outcomes[1].Job.Account.UID != 1002 {
		t.Fatalf("outcomes %+v", outcomes)
	}
}
