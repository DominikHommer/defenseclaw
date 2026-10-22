// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// useStandaloneCleanupFence makes cfg a standalone enterprise config whose
// guardian directory holds the cleanup fence, and returns that directory.
func useStandaloneCleanupFence(t *testing.T, policy map[string]config.EnterpriseConnectorPolicy) string {
	t.Helper()
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{
			Profile:       managed.ProfileStandalone,
			MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: policy},
		},
	}
	useStandaloneForeignHookFenceFixture(t)
	dir, err := prepareEnterpriseHookAuthorizationDir(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// gatewayTakesCleanupFence reports whether a gateway exchange could take
// the cleanup fence within wait.
func gatewayTakesCleanupFence(t *testing.T, guardianDir string, wait time.Duration) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	unlock, err := enterprisepolicy.LockForeignHookRemovals(ctx, filepath.Join(guardianDir, enterprisepolicy.ForeignHookCleanupFenceFile))
	if err != nil {
		return false
	}
	unlock()
	return true
}

func ledgerIdentities(t *testing.T, guardianDir string) []string {
	t.Helper()
	removals, err := loadEnterpriseForeignHookRemovals(filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var identities []string
	for _, removal := range removals {
		identities = append(identities, removal.Identity)
	}
	return identities
}

// The per-user workers run concurrently and none of their work holds the
// machine's cleanup fence: only a removal does, through its ledger commit.
// A worker that scans for a long time, or whose other tasks are slow, never
// keeps the gateway's exchanges or another account's cleanup waiting.
func TestStandaloneForeignCleanupWorkersDoNotHoldTheFence(t *testing.T) {
	previousManifest := enterpriseHookManifest
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		enterpriseHookManifest = previousManifest
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.unrepaired = nil
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	guardianDir := useStandaloneCleanupFence(t, map[string]config.EnterpriseConnectorPolicy{"cursor": {}})
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{
			{User: "alice", UID: 4242, GID: 4242, Home: "/home/alice", HomeInode: 7},
			{User: "bob", UID: 4243, GID: 4243, Home: "/home/bob", HomeInode: 7},
		}, nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
	}
	var mu sync.Mutex
	active, peak := 0, 0
	both := make(chan struct{})
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		mu.Lock()
		active++
		if active > peak {
			peak = active
		}
		if active == 2 {
			close(both)
		}
		mu.Unlock()
		defer func() {
			mu.Lock()
			active--
			mu.Unlock()
		}()
		if len(request.ForeignCleanup) == 0 {
			t.Errorf("worker for %s has no foreign cleanup", account.User)
		}
		if !gatewayTakesCleanupFence(t, guardianDir, 100*time.Millisecond) {
			t.Errorf("the worker for %s holds the cleanup fence before any removal", account.User)
		}
		select {
		case <-both:
		case <-time.After(2 * time.Second):
			t.Errorf("the worker for %s ran alone: the accounts' workers must run concurrently", account.User)
		}
		var targets []enterpriseHookWorkerTargetResult
		for _, target := range request.Targets {
			targets = append(targets, enterpriseHookWorkerTargetResult{Index: target.Index, OK: true})
		}
		return enterpriseHookWorkerResponse{Targets: targets, Cleanup: map[string]enterpriseHookWorkerCleanupReport{
			"cursor": {Removed: []string{account.Home + "/.cursor/hooks.json"}, BackupDir: account.Home + "/.defenseclaw/foreign-hooks-backup/cursor/x"},
		}}, nil
	}
	var log strings.Builder
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC), enterprisehooks.Manifest{}, map[string]map[string]bool{}, "")
	if peak != 2 {
		t.Fatalf("peak concurrent workers = %d, want 2; log:\n%s", peak, log.String())
	}
	if got := strings.Join(ledgerIdentities(t, guardianDir), ","); !strings.Contains(got, "4242") || !strings.Contains(got, "4243") {
		t.Fatalf("both accounts' removals must reach the ledger, got %q; log:\n%s", got, log.String())
	}
	if !gatewayTakesCleanupFence(t, guardianDir, 100*time.Millisecond) {
		t.Fatal("the cleanup fence is still held after the pass")
	}
}

// A cleanup that waits for another account's removals queues within its own
// bound. The short fence-file budget is only for the gateway's exchanges:
// it never abandons a queued account, and a failed take holds nothing.
func TestForeignCleanupFenceQueuesAccountsInsteadOfAbandoningThem(t *testing.T) {
	guardianDir := useStandaloneCleanupFence(t, nil)
	previousWait := enterpriseForeignHookCleanupFenceWait
	t.Cleanup(func() { enterpriseForeignHookCleanupFenceWait = previousWait })
	enterpriseForeignHookCleanupFenceWait = 50 * time.Millisecond
	cleanups := []enterpriseHookWorkerForeignCleanup{{Connector: "cursor"}, {Connector: "claudecode"}}
	session := func(uid, home string) *enterpriseForeignHookFenceSession {
		return newEnterpriseForeignHookFenceSession(cleanups, func(connector string, removed []string) {
			recordEnterpriseForeignHookRemovals(io.Discard, uid, home, connector, removed)
		})
	}
	alice, bob := session("4242", "/home/alice"), session("4243", "/home/bob")
	if err := alice.lock(context.Background(), "cursor"); err != nil {
		t.Fatal(err)
	}
	if gatewayTakesCleanupFence(t, guardianDir, 50*time.Millisecond) {
		t.Fatal("a removal in progress must hold the fence against the gateway")
	}
	queued := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		queued <- bob.lock(ctx, "cursor")
	}()
	select {
	case err := <-queued:
		t.Fatalf("bob's cleanup passed alice's removal in progress: %v", err)
	case <-time.After(6 * enterpriseForeignHookCleanupFenceWait):
	}
	if err := alice.commit("cursor", []string{"/home/alice/.cursor/hooks.json"}); err != nil {
		t.Fatal(err)
	}
	if err := <-queued; err != nil {
		t.Fatalf("a queued account's cleanup was abandoned: %v", err)
	}
	if got := strings.Join(ledgerIdentities(t, guardianDir), ","); got != "4242" {
		t.Fatalf("alice's removal must be committed before bob's cleanup goes on: ledger %q", got)
	}
	if err := bob.commit("cursor", []string{"/home/bob/.cursor/hooks.json"}); err != nil {
		t.Fatal(err)
	}
	if !gatewayTakesCleanupFence(t, guardianDir, 50*time.Millisecond) {
		t.Fatal("the fence stays held after the last commit")
	}

	// Each removal takes the fence again: a later removal of the same
	// connector gets it once the earlier one committed. The session takes no
	// fence for a connector the job did not ask for, while one of its
	// removals holds it, or past the per-connector bound, and commits only
	// for the removal that holds it.
	if err := alice.lock(context.Background(), "codex"); err == nil {
		t.Fatal("locked for a connector outside the job")
	}
	if err := alice.commit("claudecode", []string{"/home/alice/.claude/settings.json"}); err == nil {
		t.Fatal("committed without the fence")
	}
	if err := alice.lock(context.Background(), "cursor"); err != nil {
		t.Fatalf("a later removal of the same connector must take the fence again: %v", err)
	}
	if err := alice.lock(context.Background(), "claudecode"); err == nil {
		t.Fatal("locked while another removal of the job holds the fence")
	}
	if err := alice.commit("claudecode", []string{"/home/alice/.claude/settings.json"}); err == nil {
		t.Fatal("committed for a connector whose removal does not hold the fence")
	}
	if err := alice.commit("cursor", []string{"/home/alice/.cursor/other.json"}); err != nil {
		t.Fatal(err)
	}
	if err := alice.commit("cursor", nil); err == nil {
		t.Fatal("committed twice for one lock")
	}
	if got := alice.uncommitted("cursor", []string{"/home/alice/.cursor/hooks.json", "/home/alice/.cursor/other.json", "/home/alice/.cursor/late.json"}); strings.Join(got, ",") != "/home/alice/.cursor/late.json" {
		t.Fatalf("uncommitted = %v", got)
	}
	alice.locks["claudecode"] = enterpriseHookWorkerFenceLockLimit
	if err := alice.lock(context.Background(), "claudecode"); err == nil {
		alice.release()
		t.Fatal("locked past the per-connector bound")
	}
	if !gatewayTakesCleanupFence(t, guardianDir, 50*time.Millisecond) {
		t.Fatal("the fence stays held after the session's commits")
	}

	// A gateway exchange that holds the fence file past the budget refuses
	// this removal; nothing stays held, so the next cleanup gets its turn.
	gatewayUnlock, err := enterprisepolicy.LockForeignHookRemovals(context.Background(), filepath.Join(guardianDir, enterprisepolicy.ForeignHookCleanupFenceFile))
	if err != nil {
		t.Fatal(err)
	}
	carol := session("4244", "/home/carol")
	if err := carol.lock(context.Background(), "cursor"); err == nil {
		gatewayUnlock()
		t.Fatal("took the fence the gateway holds")
	}
	gatewayUnlock()
	if err := carol.lock(context.Background(), "claudecode"); err != nil {
		t.Fatalf("a refused take kept this guardian's turn: %v", err)
	}
	carol.release()
	if !gatewayTakesCleanupFence(t, guardianDir, 50*time.Millisecond) {
		t.Fatal("release left the fence held")
	}
}

// The real worker, as the user, asks for the fence only when it is about to
// remove a hook, waits while a gateway allow holds it, and hands its
// removals back for the ledger commit before it ends. A worker with nothing
// to remove never asks, so a held fence does not delay it.
func TestForeignCleanupWorkerTakesTheFenceOnlyToRemove(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "real")
	guardianDir := useStandaloneCleanupFence(t, nil)
	previousWait := enterpriseForeignHookCleanupFenceWait
	t.Cleanup(func() { enterpriseForeignHookCleanupFenceWait = previousWait })
	enterpriseForeignHookCleanupFenceWait = 20 * time.Second
	account := selfWorkerAccount(t)
	hooks := filepath.Join(account.Home, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooks), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooks, []byte(`{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cleanups := []enterpriseHookWorkerForeignCleanup{{
		Connector:  "cursor",
		HookBinary: "/opt/defenseclaw/bin/defenseclaw-hook",
		Policy:     enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true},
	}}
	var recorded [][]string
	newSession := func() *enterpriseForeignHookFenceSession {
		return newEnterpriseForeignHookFenceSession(cleanups, func(connector string, removed []string) {
			if data, _ := os.ReadFile(hooks); strings.Contains(string(data), "rewrite.sh") {
				t.Error("the ledger commit ran before the removal")
			}
			if gatewayTakesCleanupFence(t, guardianDir, 30*time.Millisecond) {
				t.Error("the fence was not held through the ledger commit")
			}
			recorded = append(recorded, removed)
			recordEnterpriseForeignHookRemovals(io.Discard, "4242", account.Home, connector, removed)
		})
	}
	run := func(session *enterpriseForeignHookFenceSession) <-chan error {
		done := make(chan error, 1)
		go func() {
			response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
				Operation: enterpriseHookWorkerOpForeignCleanup, Standalone: true, ForeignCleanup: cleanups, cleanupFence: session,
			})
			if err == nil && response.Cleanup["cursor"].Error != "" {
				t.Errorf("cleanup report: %+v", response.Cleanup["cursor"])
			}
			done <- err
		}()
		return done
	}

	// A gateway allow holds the fence: the worker's removal waits for it.
	gatewayUnlock, err := enterprisepolicy.LockForeignHookRemovals(context.Background(), filepath.Join(guardianDir, enterprisepolicy.ForeignHookCleanupFenceFile))
	if err != nil {
		t.Fatal(err)
	}
	done := run(newSession())
	deadline := time.Now().Add(20 * time.Second)
	for len(enterpriseForeignHookCleanupQueue) == 0 && time.Now().Before(deadline) {
		select {
		case err := <-done:
			gatewayUnlock()
			t.Fatalf("the worker ended without asking for the fence: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if len(enterpriseForeignHookCleanupQueue) == 0 {
		gatewayUnlock()
		t.Fatal("the worker never asked for the fence")
	}
	if data, _ := os.ReadFile(hooks); !strings.Contains(string(data), "rewrite.sh") {
		gatewayUnlock()
		t.Fatal("the worker removed the hook while a gateway allow held the fence")
	}
	gatewayUnlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(hooks); strings.Contains(string(data), "rewrite.sh") {
		t.Fatalf("the foreign hook is still registered: %s", data)
	}
	if len(recorded) != 1 || len(recorded[0]) != 1 || recorded[0][0] != hooks {
		t.Fatalf("committed removals %v", recorded)
	}
	if got := ledgerIdentities(t, guardianDir); len(got) != 1 {
		t.Fatalf("ledger %v", got)
	}
	if !gatewayTakesCleanupFence(t, guardianDir, 100*time.Millisecond) {
		t.Fatal("the fence is still held after the worker ended")
	}

	// Nothing left to remove: the worker finishes while the gateway holds
	// the fence, without asking for it.
	gatewayUnlock, err = enterprisepolicy.LockForeignHookRemovals(context.Background(), filepath.Join(guardianDir, enterprisepolicy.ForeignHookCleanupFenceFile))
	if err != nil {
		t.Fatal(err)
	}
	defer gatewayUnlock()
	start := time.Now()
	if err := <-run(newSession()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second || len(recorded) != 1 || len(enterpriseForeignHookCleanupQueue) != 0 {
		t.Fatalf("a clean home waited %v for the fence (commits %d)", elapsed, len(recorded))
	}
}

// The worker releases the fence after each removal, before it reads on: a
// cleanup with two foreign plugins takes and commits the fence once per
// plugin, and the second plugin is untouched when the first one commits. A
// refused fence leaves every hook in place, asked for once.
func TestForeignCleanupWorkerReleasesTheFenceAfterEachRemoval(t *testing.T) {
	setup := func(t *testing.T) (string, []string, []enterpriseHookWorkerForeignCleanup) {
		home := t.TempDir()
		dir := filepath.Join(home, ".config", "opencode", "plugins")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		plugins := []string{filepath.Join(dir, "a-mutate.mjs"), filepath.Join(dir, "b-mutate.mjs")}
		for _, path := range plugins {
			if err := os.WriteFile(path, []byte("export default {}"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return home, plugins, []enterpriseHookWorkerForeignCleanup{{
			Connector:  "opencode",
			HookBinary: "/opt/defenseclaw/bin/defenseclaw-hook",
			Policy:     enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true},
		}}
	}
	present := func(path string) bool { _, err := os.Lstat(path); return err == nil }

	home, plugins, cleanups := setup(t)
	fence := &recordingCleanupFence{}
	commits := 0
	fence.onCommit = func(removed []string) {
		commits++
		if commits == 1 && (len(removed) != 1 || present(removed[0]) || !present(plugins[0]) && !present(plugins[1])) {
			t.Errorf("the first commit must cover one removed plugin while the other is still in place: %v", removed)
		}
	}
	reports := runEnterpriseHookWorkerForeignCleanup(enterpriseHookWorkerRequest{Home: home, ForeignCleanup: cleanups}, time.Now(), fence)
	report := reports["opencode"]
	if report.Error != "" || len(report.Removed) != 2 {
		t.Fatalf("cleanup report %+v", report)
	}
	locks := 0
	for _, event := range fence.events {
		if strings.HasPrefix(event, "lock ") {
			locks++
		}
	}
	if locks != 2 || commits != 2 || len(fence.events) != 4 || fence.held {
		t.Fatalf("each removal must take and release the fence on its own: %v", fence.events)
	}
	for _, path := range plugins {
		if present(path) {
			t.Fatalf("%s was not removed", path)
		}
	}

	home, plugins, cleanups = setup(t)
	refused := &recordingCleanupFence{lockErr: errors.New("fence busy")}
	report = runEnterpriseHookWorkerForeignCleanup(enterpriseHookWorkerRequest{Home: home, ForeignCleanup: cleanups}, time.Now(), refused)["opencode"]
	if report.Error == "" || len(report.Removed) != 0 || len(report.Reported) < 2 || len(refused.events) != 1 {
		t.Fatalf("a refused fence: report %+v, fence %v", report, refused.events)
	}
	for _, path := range plugins {
		if !present(path) {
			t.Fatalf("%s was removed without the fence", path)
		}
	}
}
