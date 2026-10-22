// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// recordingCleanupFence is a cleanup fence that records its use.
type recordingCleanupFence struct {
	events    []string
	held      bool
	lockErr   error
	commitErr error
	onCommit  func(removed []string)
}

func (f *recordingCleanupFence) lock(connector string) error {
	f.events = append(f.events, "lock "+connector)
	if f.lockErr != nil {
		return f.lockErr
	}
	if f.held {
		return errors.New("locked while held")
	}
	f.held = true
	return nil
}

func (f *recordingCleanupFence) commit(connector string, removed []string) error {
	f.events = append(f.events, "commit "+connector+" "+strings.Join(removed, ","))
	if !f.held {
		return errors.New("committed without the fence")
	}
	f.held = false
	if f.onCommit != nil {
		f.onCommit(removed)
	}
	return f.commitErr
}

// useInProcessCleanupFence makes cfg a standalone enterprise config whose
// guardian directory holds the cleanup fence, and returns that directory.
func useInProcessCleanupFence(t *testing.T) string {
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

// cleanupFenceFree reports whether a gateway exchange could take the
// cleanup fence within wait.
func cleanupFenceFree(guardianDir string, wait time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	unlock, err := enterprisepolicy.LockForeignHookRemovals(ctx, filepath.Join(guardianDir, enterprisepolicy.ForeignHookCleanupFenceFile))
	if err != nil {
		return false
	}
	unlock()
	return true
}

// Each removal takes the fence on its own and commits only what it
// removed; a refused fence or a failed commit stops the cleanup's later
// removals without waiting again.
func TestForeignHookRemovalGuardFencesEachRemovalOnItsOwn(t *testing.T) {
	fence := &recordingCleanupFence{}
	guard := enterpriseForeignHookRemovalGuard("cursor", fence)
	for _, path := range []string{"/home/a/one.json", "/home/a/two.json"} {
		if err := guard([]string{path}, func() error {
			if !fence.held {
				t.Errorf("%s was removed without the fence", path)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if fence.held {
			t.Fatalf("the fence is still held after %s was committed", path)
		}
	}
	failed := errors.New("rewrite failed")
	if err := guard([]string{"/home/a/three.json"}, func() error { return failed }); !errors.Is(err, failed) {
		t.Fatalf("a failed removal must return its error, got %v", err)
	}
	want := "lock cursor|commit cursor /home/a/one.json|lock cursor|commit cursor /home/a/two.json|lock cursor|commit cursor "
	if got := strings.Join(fence.events, "|"); got != want {
		t.Fatalf("fence use\n got %s\nwant %s", got, want)
	}

	refused := &recordingCleanupFence{lockErr: errors.New("fence busy")}
	guard = enterpriseForeignHookRemovalGuard("cursor", refused)
	for i := 0; i < 2; i++ {
		if err := guard([]string{"/home/a/one.json"}, func() error {
			t.Error("a removal ran without the fence")
			return nil
		}); !errors.Is(err, refused.lockErr) {
			t.Fatalf("a refused fence must refuse the removal, got %v", err)
		}
	}
	if len(refused.events) != 1 {
		t.Fatalf("a refused fence was asked again: %v", refused.events)
	}

	broken := &recordingCleanupFence{commitErr: errors.New("fence pipe closed")}
	guard = enterpriseForeignHookRemovalGuard("cursor", broken)
	if err := guard([]string{"/home/a/one.json"}, func() error { return nil }); !errors.Is(err, broken.commitErr) {
		t.Fatalf("a failed commit must surface, got %v", err)
	}
	if err := guard([]string{"/home/a/two.json"}, func() error {
		t.Error("a removal ran after a failed commit")
		return nil
	}); err == nil {
		t.Fatal("a removal after a failed commit must be refused")
	}
	if len(broken.events) != 2 {
		t.Fatalf("fence use after a failed commit: %v", broken.events)
	}
}

// The reconcile loop's foreign-hook cleanup holds no fence of its own: a
// cleanup that is scanning, or that removes nothing, never keeps another
// account's gateway exchanges waiting.
func TestReconcileForeignHooksHoldsNoFenceWhileItCleans(t *testing.T) {
	guardianDir := useInProcessCleanupFence(t)
	previousCleanup := enterpriseForeignHookCleanup
	t.Cleanup(func() { enterpriseForeignHookCleanup = previousCleanup })
	calls := 0
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		calls++
		if !cleanupFenceFree(guardianDir, 200*time.Millisecond) {
			t.Error("the reconcile cleanup holds the cleanup fence while it scans")
		}
		return enterprisepolicy.CleanupResult{}, nil
	}
	reconcileEnterpriseForeignHooks(enterprisehooks.InstallOptions{ConnectorName: "cursor", UserHome: t.TempDir(), OwnerUID: 4242, OwnerGID: 4242})
	if calls != 1 {
		t.Fatalf("cleanup calls = %d", calls)
	}
}

// The guardian's in-process cleanup takes the fence only to remove: its
// removal waits while a gateway allow holds the fence and is committed to
// the ledger; a cleanup with nothing to remove finishes while the gateway
// holds the fence, without asking for it.
func TestInProcessForeignCleanupTakesTheFenceOnlyToRemove(t *testing.T) {
	guardianDir := useInProcessCleanupFence(t)
	previousWait, previousRunAs := enterpriseForeignHookCleanupFenceWait, enterpriseForeignHookRunAsTarget
	t.Cleanup(func() {
		enterpriseForeignHookCleanupFenceWait, enterpriseForeignHookRunAsTarget = previousWait, previousRunAs
	})
	enterpriseForeignHookCleanupFenceWait = 20 * time.Second
	enterpriseForeignHookRunAsTarget = func(_ enterprisehooks.TargetCredentials, fn func() error) error { return fn() }
	home := t.TempDir()
	hooks := filepath.Join(home, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooks), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooks, []byte(`{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	target := enterprisehooks.TargetCredentials{UserHome: home, UID: 4242, GID: 4242}
	if runtime.GOOS == "windows" {
		target = enterprisehooks.TargetCredentials{UserHome: home, UID: -1, GID: -1, SID: "S-1-5-21-1-2-3-1001"}
	}
	request := enterprisepolicy.GuardRequest{
		Connector:   "cursor",
		GOOS:        runtime.GOOS,
		Home:        home,
		AccountHome: home,
		HookBinary:  "/opt/defenseclaw/bin/defenseclaw-hook",
		Policy:      enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true},
	}
	type outcome struct {
		result enterprisepolicy.CleanupResult
		err    error
	}
	run := func() <-chan outcome {
		done := make(chan outcome, 1)
		go func() {
			result, err := cleanEnterpriseForeignHooksFenced(target, request, time.Now())
			done <- outcome{result, err}
		}()
		return done
	}
	ledger := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)

	gatewayUnlock, err := enterprisepolicy.LockForeignHookRemovals(context.Background(), filepath.Join(guardianDir, enterprisepolicy.ForeignHookCleanupFenceFile))
	if err != nil {
		t.Fatal(err)
	}
	done := run()
	deadline := time.Now().Add(10 * time.Second)
	for len(enterpriseForeignHookCleanupQueue) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(enterpriseForeignHookCleanupQueue) == 0 {
		gatewayUnlock()
		t.Fatal("the cleanup never asked for the fence")
	}
	if data, _ := os.ReadFile(hooks); !strings.Contains(string(data), "rewrite.sh") {
		gatewayUnlock()
		t.Fatal("the cleanup removed the hook while a gateway allow held the fence")
	}
	gatewayUnlock()
	first := <-done
	if runtime.GOOS != "windows" && first.err != nil {
		t.Fatal(first.err)
	}
	if len(first.result.Removed) != 1 {
		t.Fatalf("cleanup result %+v (%v)", first.result, first.err)
	}
	if data, _ := os.ReadFile(hooks); strings.Contains(string(data), "rewrite.sh") {
		t.Fatalf("the foreign hook is still registered: %s", data)
	}
	removals, err := loadEnterpriseForeignHookRemovals(ledger)
	if err != nil || len(removals) != 1 {
		t.Fatalf("the removal was not committed once: %+v, %v", removals, err)
	}
	if !cleanupFenceFree(guardianDir, 100*time.Millisecond) || len(enterpriseForeignHookCleanupQueue) != 0 {
		t.Fatal("the fence is still held after the cleanup")
	}

	// Nothing left to remove: the cleanup finishes while the gateway holds
	// the fence, without asking for it.
	gatewayUnlock, err = enterprisepolicy.LockForeignHookRemovals(context.Background(), filepath.Join(guardianDir, enterprisepolicy.ForeignHookCleanupFenceFile))
	if err != nil {
		t.Fatal(err)
	}
	defer gatewayUnlock()
	select {
	case second := <-run():
		if len(second.result.Removed) != 0 || (runtime.GOOS != "windows" && second.err != nil) {
			t.Fatalf("a clean config: %+v (%v)", second.result, second.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cleanup with nothing to remove waited for the fence")
	}
	if removals, _ := loadEnterpriseForeignHookRemovals(ledger); len(removals) != 1 {
		t.Fatalf("a clean config changed the ledger: %+v", removals)
	}
}
