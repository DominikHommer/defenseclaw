// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestGuardianCommitsForeignHookRemovalUnderTheResponseFence(t *testing.T) {
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
	done := make(chan string, 1)
	go func() {
		var stderr bytes.Buffer
		recordEnterpriseForeignHookRemovals(&stderr, "1001", "/home/alice", "claudecode", []string{"/home/alice/.claude/settings.json"})
		done <- stderr.String()
	}()
	ledger := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	select {
	case message := <-done:
		unlock()
		t.Fatalf("guardian passed the held response fence: %s", message)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := os.Stat(ledger); !os.IsNotExist(err) {
		unlock()
		t.Fatalf("guardian published before the response finished: %v", err)
	}
	unlock()
	select {
	case message := <-done:
		if message != "" {
			t.Fatal(message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("guardian did not commit after the response")
	}
	removals, err := loadEnterpriseForeignHookRemovals(ledger)
	if err != nil || len(removals) != 1 || removals[0].Identity != "1001" {
		t.Fatalf("committed removals = %+v, %v", removals, err)
	}
	after, err := os.Stat(fence)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the permanent response fence was replaced: %v", err)
	}
}

// A guardian removal commit lands under sustained online exchanges that
// overlap so the fence is never free, from this process or another one:
// the pending commit admits no new exchange and waits only for those
// already answering.
func TestGuardianRemovalCommitLandsUnderSustainedExchanges(t *testing.T) {
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
	var holders, served atomic.Int64
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
					continue
				}
				holders.Add(1)
				served.Add(1)
				time.Sleep(40 * time.Millisecond)
				holders.Add(-1)
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
	done := make(chan string, 1)
	go func() {
		var stderr bytes.Buffer
		recordEnterpriseForeignHookRemovals(&stderr, "1001", "/home/alice", "claudecode", []string{"/home/alice/.claude/settings.json"})
		done <- stderr.String()
	}()
	select {
	case message := <-done:
		if message != "" {
			t.Fatal(message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sustained online exchanges starved the guardian's removal commit")
	}
	removals, err := loadEnterpriseForeignHookRemovals(filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile))
	if err != nil || len(removals) != 1 || removals[0].Identity != "1001" {
		t.Fatalf("committed removals = %+v, %v", removals, err)
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
	turnstile := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsTurnstileFile)
	created, err := os.Stat(turnstile)
	if err != nil || !created.Mode().IsRegular() || created.Size() != 0 {
		t.Fatalf("reconcile did not create the turnstile: %v", err)
	}
	unlock, err := enterprisepolicy.LockForeignHookRemovalsCommit(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := ensureEnterpriseForeignHookRemovalFence(dir); err != nil {
		t.Fatal(err)
	}
	again, err := os.Stat(turnstile)
	if err != nil || !os.SameFile(created, again) {
		t.Fatalf("reconcile replaced the existing turnstile: %v", err)
	}
	// A lock file that is not empty and regular is refused, never replaced.
	if err := os.WriteFile(turnstile, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := ensureEnterpriseForeignHookRemovalFence(dir); err == nil {
		t.Fatal("reconcile accepted a non-empty turnstile")
	}
}

// A guardian commit waiting for an allow being written goes before the
// exchanges that arrive after it: each of them takes the fence only once
// the ledger holds the removal.
func TestGuardianPendingRemovalCommitGoesBeforeLaterExchanges(t *testing.T) {
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
	ledger := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	held, err := enterprisepolicy.LockForeignHookRemovalsExchange(context.Background(), guardianDir)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		var stderr bytes.Buffer
		recordEnterpriseForeignHookRemovals(&stderr, "1001", "/home/alice", "claudecode", []string{"/home/alice/.claude/settings.json"})
		done <- stderr.String()
	}()
	// Wait until the commit is pending: a new exchange cannot take the
	// fence, although the held exchange holds it only shared.
	deadline := time.Now().Add(3 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
		unlock, err := enterprisepolicy.LockForeignHookRemovalsExchange(ctx, guardianDir)
		cancel()
		if err != nil {
			break
		}
		unlock()
		if time.Now().After(deadline) {
			held()
			t.Fatal("the guardian's commit never became pending")
		}
		time.Sleep(time.Millisecond)
	}
	sawLedger := make(chan bool, 4)
	for i := 0; i < 4; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			unlock, err := enterprisepolicy.LockForeignHookRemovalsExchange(ctx, guardianDir)
			if err != nil {
				sawLedger <- false
				return
			}
			_, statErr := os.Stat(ledger)
			unlock()
			sawLedger <- statErr == nil
		}()
	}
	time.Sleep(50 * time.Millisecond)
	held()
	for i := 0; i < 4; i++ {
		select {
		case ok := <-sawLedger:
			if !ok {
				t.Fatal("an exchange that arrived after a pending removal commit took the fence before the commit")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("an exchange behind the commit never took the fence")
		}
	}
	if message := <-done; message != "" {
		t.Fatal(message)
	}
}
