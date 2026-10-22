// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// setupForeignHookRemovalGuardian points the guardian at a temporary
// standalone data directory with trusted ownership and returns the
// guardian's directory.
func setupForeignHookRemovalGuardian(t *testing.T) string {
	t.Helper()
	previousCfg := cfg
	previousOwner := enterpriseHookAuthorizationOwnershipSetter
	previousDirTrust := enterpriseHookAuthorizationDirTrustCheck
	previousFileTrust := enterpriseHookAuthorizationFileTrustCheck
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookAuthorizationOwnershipSetter = previousOwner
		enterpriseHookAuthorizationDirTrustCheck = previousDirTrust
		enterpriseHookAuthorizationFileTrustCheck = previousFileTrust
	})
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	dataDir := t.TempDir()
	guardianDir := filepath.Join(dataDir, "guardian")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	if _, err := prepareEnterpriseHookAuthorizationDir(dataDir); err != nil {
		t.Fatal(err)
	}
	return guardianDir
}

func recordAliceForeignHookRemoval() <-chan string {
	done := make(chan string, 1)
	go func() {
		var stderr bytes.Buffer
		recordEnterpriseForeignHookRemovals(&stderr, "1001", "/home/alice", "claudecode", []string{"/home/alice/.claude/settings.json"})
		done <- stderr.String()
	}()
	return done
}

// waitForAliceForeignHookRemoval waits until the ledger records alice's
// removal.
func waitForAliceForeignHookRemoval(t *testing.T, guardianDir string, within time.Duration) {
	t.Helper()
	ledger := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	deadline := time.Now().Add(within)
	for {
		removals, err := loadEnterpriseForeignHookRemovals(ledger)
		if err == nil && len(removals) == 1 && removals[0].Identity == "1001" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the ledger did not record the removal within %v: %+v, %v", within, removals, err)
		}
		time.Sleep(time.Millisecond)
	}
}

// GAP-0348: the guardian publishes the removal at once and then waits for
// the allow being written, which may have read the previous ledger.
func TestGuardianCommitsForeignHookRemovalUnderTheResponseFence(t *testing.T) {
	guardianDir := setupForeignHookRemovalGuardian(t)
	fence := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFenceFile)
	before, err := os.Stat(fence)
	if err != nil {
		t.Fatal(err)
	}
	// An online allow being written holds the fence shared.
	unlock, err := enterprisepolicy.LockForeignHookRemovalsExchange(context.Background(), guardianDir)
	if err != nil {
		t.Fatal(err)
	}
	done := recordAliceForeignHookRemoval()
	waitForAliceForeignHookRemoval(t, guardianDir, time.Second)
	select {
	case message := <-done:
		unlock()
		t.Fatalf("guardian went on past the allow being written: %s", message)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case message := <-done:
		if message != "" {
			t.Fatal(message)
		}
	case <-time.After(enterprisepolicy.ForeignHookRemovalDrainWait):
		t.Fatal("guardian did not finish after the response")
	}
	after, err := os.Stat(fence)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the permanent response fence was replaced: %v", err)
	}
}

// A guardian removal commit lands under sustained online exchanges that
// overlap so the fence is never free: it publishes at once and waits for
// the exchanges for a bounded time only.
func TestGuardianRemovalCommitLandsUnderSustainedExchanges(t *testing.T) {
	guardianDir := setupForeignHookRemovalGuardian(t)
	var served atomic.Int64
	var refused atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 10 * time.Millisecond)
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				unlock, err := enterprisepolicy.LockForeignHookRemovalsExchange(ctx, guardianDir)
				cancel()
				if err != nil {
					refused.Add(1)
					continue
				}
				served.Add(1)
				time.Sleep(40 * time.Millisecond)
				unlock()
			}
		}(i)
	}
	t.Cleanup(func() {
		close(stop)
		wg.Wait()
	})
	for served.Load() < 8 {
		time.Sleep(time.Millisecond)
	}
	done := recordAliceForeignHookRemoval()
	waitForAliceForeignHookRemoval(t, guardianDir, 500*time.Millisecond)
	select {
	case message := <-done:
		if message != "" {
			t.Fatal(message)
		}
	case <-time.After(enterprisepolicy.ForeignHookRemovalDrainWait + 2*time.Second):
		t.Fatal("sustained online exchanges starved the guardian's removal commit")
	}
	if n := refused.Load(); n != 0 {
		t.Fatalf("%d exchanges were refused during the commit", n)
	}
}

// Reconcile creates the fence's lock files that are missing, as on an
// upgrade from a build that had only the fence, and keeps those that exist.
func TestEnsureForeignHookRemovalFenceCreatesMissingLockFilesOnly(t *testing.T) {
	previousOwner := enterpriseHookAuthorizationOwnershipSetter
	previousFileTrust := enterpriseHookAuthorizationFileTrustCheck
	t.Cleanup(func() {
		enterpriseHookAuthorizationOwnershipSetter = previousOwner
		enterpriseHookAuthorizationFileTrustCheck = previousFileTrust
	})
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	dir := t.TempDir()
	fence := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsFenceFile)
	if err := os.WriteFile(fence, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(fence)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureEnterpriseForeignHookRemovalFence(dir); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(fence)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("reconcile replaced the existing fence: %v", err)
	}
	ledgerLock := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsLedgerLockFile)
	created, err := os.Stat(ledgerLock)
	if err != nil || !created.Mode().IsRegular() || created.Size() != 0 {
		t.Fatalf("reconcile did not create the ledger lock: %v", err)
	}
	unlock, err := enterprisepolicy.LockForeignHookRemovalsLedger(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := ensureEnterpriseForeignHookRemovalFence(dir); err != nil {
		t.Fatal(err)
	}
	again, err := os.Stat(ledgerLock)
	if err != nil || !os.SameFile(created, again) {
		t.Fatalf("reconcile replaced the existing ledger lock: %v", err)
	}
	// A lock file that is not empty and regular is refused, never replaced.
	if err := os.WriteFile(ledgerLock, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := ensureEnterpriseForeignHookRemovalFence(dir); err == nil {
		t.Fatal("reconcile accepted a non-empty ledger lock")
	}
}

// While the guardian waits for an allow being written, exchanges that
// arrive after the publication take the fence at once and read the ledger
// with the removal: a pending removal holds up no exchange.
func TestGuardianPublishedRemovalIsSeenByLaterExchangesAtOnce(t *testing.T) {
	guardianDir := setupForeignHookRemovalGuardian(t)
	ledger := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	held, err := enterprisepolicy.LockForeignHookRemovalsExchange(context.Background(), guardianDir)
	if err != nil {
		t.Fatal(err)
	}
	done := recordAliceForeignHookRemoval()
	waitForAliceForeignHookRemoval(t, guardianDir, time.Second)
	for i := 0; i < 4; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		unlock, err := enterprisepolicy.LockForeignHookRemovalsExchange(ctx, guardianDir)
		cancel()
		if err != nil {
			held()
			t.Fatalf("an exchange after the publication waited on the pending commit: %v", err)
		}
		removals, loadErr := loadEnterpriseForeignHookRemovals(ledger)
		unlock()
		if loadErr != nil || len(removals) != 1 {
			held()
			t.Fatalf("an exchange after the publication read %+v, %v", removals, loadErr)
		}
	}
	select {
	case message := <-done:
		held()
		t.Fatalf("the guardian went on past the allow being written: %s", message)
	default:
	}
	held()
	if message := <-done; message != "" {
		t.Fatal(message)
	}
}

// A ledger publication that is slow (staging, sync, ownership, trust
// checks) never refuses an exchange: the guardian does all of it before it
// touches the fence, which it then holds only for a moment.
func TestGuardianSlowLedgerPublicationDoesNotRefuseExchanges(t *testing.T) {
	guardianDir := setupForeignHookRemovalGuardian(t)
	enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
		if !strings.HasSuffix(path, ".lock") {
			time.Sleep(650 * time.Millisecond)
		}
		return nil
	}
	done := recordAliceForeignHookRemoval()
	var attempts, refused int
	for finished := false; !finished; {
		select {
		case message := <-done:
			if message != "" {
				t.Fatal(message)
			}
			finished = true
			continue
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		unlock, err := enterprisepolicy.LockForeignHookRemovalsExchange(ctx, guardianDir)
		cancel()
		attempts++
		if err != nil {
			refused++
			continue
		}
		unlock()
		time.Sleep(5 * time.Millisecond)
	}
	if refused != 0 || attempts < 20 {
		t.Fatalf("%d of %d exchanges were refused during a slow ledger publication", refused, attempts)
	}
	waitForAliceForeignHookRemoval(t, guardianDir, 0)
}

// A fence or ledger lock that is not an empty regular file makes the
// gateway refuse every exchange, and the guardian still records the
// removal: once the file is repaired, the process that loaded the removed
// hook must still be denied.
func TestGuardianRecordsTheRemovalWhenALockFileIsUnusable(t *testing.T) {
	for _, name := range enterprisepolicy.ForeignHookRemovalFenceFiles() {
		for _, state := range []string{"content", "directory"} {
			t.Run(name+"/"+state, func(t *testing.T) {
				guardianDir := setupForeignHookRemovalGuardian(t)
				previousWait := foreignHookRemovalLedgerLockWait
				foreignHookRemovalLedgerLockWait = 100 * time.Millisecond
				t.Cleanup(func() { foreignHookRemovalLedgerLockWait = previousWait })
				path := filepath.Join(guardianDir, name)
				var err error
				if state == "content" {
					err = os.WriteFile(path, []byte("x"), 0o640)
				} else if err = os.Remove(path); err == nil {
					err = os.Mkdir(path, 0o750)
				}
				if err != nil {
					t.Fatal(err)
				}
				var message string
				select {
				case message = <-recordAliceForeignHookRemoval():
				case <-time.After(enterprisepolicy.ForeignHookRemovalDrainWait + 2*time.Second):
					t.Fatal("the guardian did not finish")
				}
				if !strings.Contains(message, "foreign-hook removal fence") {
					t.Fatalf("the unusable lock file was not reported: %q", message)
				}
				waitForAliceForeignHookRemoval(t, guardianDir, 0)
			})
		}
	}
}
