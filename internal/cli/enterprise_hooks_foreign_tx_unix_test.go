// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// foreignTxClock returns this host's agentprocess goos, boot and clock, so
// a test can name agent processes that started before or after a mark.
func foreignTxClock(t *testing.T) (string, string, int64) {
	t.Helper()
	parts := strings.Split(agentprocess.Now(), ":")
	if len(parts) != 3 {
		t.Skip("the process clock is unavailable")
	}
	clock, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return parts[0], parts[1], clock
}

// foreignTxLedger is the removal ledger of the test's guardian.
func foreignTxLedger(dataDir string) string {
	return filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), enterprisepolicy.ForeignHookRemovalsFile)
}

// resetForeignTxs drops the cleanup transactions a test leaves behind.
func resetForeignTxs(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		enterpriseForeignHookRemovalsMu.Lock()
		defer enterpriseForeignHookRemovalsMu.Unlock()
		clear(enterpriseForeignHookCleanupTxs)
	})
}

func writeForeignTxLedger(t *testing.T, dataDir string, entries []enterprisepolicy.ForeignHookRemoval) {
	t.Helper()
	data, err := enterprisepolicy.EncodeForeignHookRemovals(entries, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareEnterpriseHookAuthorizationDir(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreignTxLedger(dataDir), data, 0o640); err != nil {
		t.Fatal(err)
	}
}

func readForeignTxLedger(t *testing.T, dataDir string) []enterprisepolicy.ForeignHookRemoval {
	t.Helper()
	entries, err := loadEnterpriseForeignHookRemovals(foreignTxLedger(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func foreignTxPending(entries []enterprisepolicy.ForeignHookRemoval) []enterprisepolicy.ForeignHookRemoval {
	return slices.DeleteFunc(slices.Clone(entries), func(r enterprisepolicy.ForeignHookRemoval) bool {
		return !enterprisepolicy.ForeignHookCleanupPending(r.Path)
	})
}

// foreignTxCall is the gateway's decision for an agent process of account
// and connector that started at start, given the ledger.
func foreignTxCall(t *testing.T, entries []enterprisepolicy.ForeignHookRemoval, account, connectorName, process string) enterprisepolicy.GuardDecision {
	t.Helper()
	var mine []enterprisepolicy.ForeignHookRemoval
	for _, entry := range entries {
		if entry.Identity == account {
			mine = append(mine, entry)
		}
	}
	return enterprisepolicy.ApplyForeignHookSession(enterprisepolicy.SessionUpdate{
		AccountHome: t.TempDir(), StateDir: t.TempDir(),
		Key:      enterprisepolicy.SessionKey{Connector: connectorName, Session: "s", Process: process},
		Removals: mine, Now: time.Now(),
	})
}

// useForeignTxPass sets up a standalone guardian with Cursor and Codex
// governed, Cursor's foreign hooks removed, and one eligible account (uid
// 4242), whose worker is worker.
func useForeignTxPass(t *testing.T, worker func(enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error)) string {
	t.Helper()
	resetForeignTxs(t)
	dataDir := useUserCleanupStateDir(t)
	previousCfg, previousManifest := cfg, enterpriseHookManifest
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = previousCfg, previousManifest
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.unrepaired = nil
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	cfg = &config.Config{
		DataDir:        dataDir,
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{
			Profile: managed.ProfileStandalone,
			MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{
				"cursor": {}, "codex": {},
			}},
		},
	}
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{{User: "alice", UID: 4242, GID: 4242, Home: "/home/alice", HomeInode: 7}}, nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
	}
	enterpriseHookWorkerRunner = func(_ context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response, err := worker(request)
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{Index: target.Index, OK: true})
		}
		return response, err
	}
	return dataDir
}

func runForeignTxPass(t *testing.T) string {
	t.Helper()
	var log bytes.Buffer
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Now(), enterprisehooks.Manifest{}, map[string]map[string]bool{"alice": {"codex": true}}, "")
	return log.String()
}

// foreignTxPlanning reports whether request is a pass's first worker,
// which only plans its foreign-hook cleanup.
func foreignTxPlanning(request enterpriseHookWorkerRequest) bool {
	return len(request.ForeignCleanup) > 0 && request.ForeignCleanup[0].Plan
}

// foreignTxPlan is a planning worker's answer: the files each connector's
// cleanup would edit.
func foreignTxPlan(files map[string][]string) enterpriseHookWorkerResponse {
	reports := map[string]enterpriseHookWorkerCleanupReport{}
	for name, paths := range files {
		reports[name] = enterpriseHookWorkerCleanupReport{Planned: paths}
	}
	return enterpriseHookWorkerResponse{Cleanup: reports}
}

// foreignTxPendingConnectors names the connectors of uid 4242's pending
// denials in the ledger.
func foreignTxPendingConnectors(dataDir string) string {
	entries, _ := loadEnterpriseForeignHookRemovals(foreignTxLedger(dataDir))
	connectors := []string{}
	for _, entry := range foreignTxPending(entries) {
		if entry.Identity == "4242" {
			connectors = append(connectors, entry.Connector)
		}
	}
	slices.Sort(connectors)
	return strings.Join(connectors, ",")
}

// Every cleanup transaction of a pass ends: a pending denial never outlives
// its worker, whatever the worker did. A cleanup that cannot tell what it
// changed leaves removals at its end, which deny the account's agents of
// the connectors that may load a planned file that started earlier, and
// let later ones (also a new account that reuses the uid) run; a cleanup
// that removed nothing leaves the ledger as it was, also when it is full.
func TestForeignHookCleanupTransactionEndsWithItsWorker(t *testing.T) {
	const hook = "/home/alice/.cursor/hooks.json"
	for _, tc := range []struct {
		name       string
		full       bool
		response   enterpriseHookWorkerResponse
		err        error
		incomplete bool
		removed    bool
	}{
		{name: "nothing removed on a full ledger", full: true, response: enterpriseHookWorkerResponse{Cleanup: map[string]enterpriseHookWorkerCleanupReport{"cursor": {}}}},
		{name: "clean removal", response: enterpriseHookWorkerResponse{Cleanup: map[string]enterpriseHookWorkerCleanupReport{"cursor": {Removed: []string{hook}}}}, removed: true},
		{name: "worker failed", err: errors.New("worker killed"), incomplete: true},
		{name: "worker did not answer for the connector", response: enterpriseHookWorkerResponse{Cleanup: map[string]enterpriseHookWorkerCleanupReport{}}, incomplete: true},
		{name: "edit failed after a removal", response: enterpriseHookWorkerResponse{Cleanup: map[string]enterpriseHookWorkerCleanupReport{
			"cursor": {Removed: []string{hook}, Error: "rename: read-only file system", Uncertain: true}}}, incomplete: true, removed: true},
		{name: "full ledger and a failed worker", full: true, err: errors.New("worker killed"), incomplete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			goos, boot, start := foreignTxClock(t)
			oldAgent := fmt.Sprintf("%s:%s:4343:%d", goos, boot, start)
			var dataDir string
			sawPending := false
			var cleaned [][]string
			dataDir = useForeignTxPass(t, func(request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				if foreignTxPlanning(request) {
					if got := foreignTxPendingConnectors(dataDir); got != "" {
						t.Errorf("the planning worker ran with pending denials for %s", got)
					}
					return foreignTxPlan(map[string][]string{"cursor": {hook}}), nil
				}
				// The cleaning worker cleans only the planned file, after
				// the denial for the connectors that load it is published.
				for _, cleanup := range request.ForeignCleanup {
					cleaned = append(cleaned, append([]string{cleanup.Connector}, cleanup.Files...))
				}
				sawPending = foreignTxPendingConnectors(dataDir) == "cursor"
				return tc.response, tc.err
			})
			var fixture []enterprisepolicy.ForeignHookRemoval
			if tc.full {
				// 1024 live removals; only the oldest was recorded after the
				// old agent started.
				now := time.Now().UTC()
				for i := 0; i < 1024; i++ {
					mark, at := fmt.Sprintf("%s:%s:%d", goos, boot, start-1000), now.Add(-time.Hour+time.Duration(i)*time.Millisecond)
					if i == 0 {
						mark, at = fmt.Sprintf("%s:%s:%d", goos, boot, start+1), now.Add(-2*time.Hour)
					}
					fixture = append(fixture, enterprisepolicy.ForeignHookRemoval{Identity: "4242", Connector: "cursor",
						Path: "/home/alice/hooks-" + strconv.Itoa(i) + ".json", At: at.Format(time.RFC3339Nano), Mark: mark})
				}
				writeForeignTxLedger(t, dataDir, fixture)
			}
			log := runForeignTxPass(t)
			if !sawPending || len(cleaned) != 1 || !slices.Equal(cleaned[0], []string{"cursor", hook}) {
				t.Fatalf("the cleaning worker ran with cleanups %v and the pending denial %t; log:\n%s", cleaned, sawPending, log)
			}
			ledger := readForeignTxLedger(t, dataDir)
			if pending := foreignTxPending(ledger); len(pending) != 0 {
				t.Fatalf("the pass left pending denials %+v; log:\n%s", pending, log)
			}
			if len(enterpriseForeignHookCleanupTxs) != 0 {
				t.Fatalf("the pass left open transactions: %v", enterpriseForeignHookCleanupTxs)
			}
			for _, want := range fixture {
				if !slices.Contains(ledger, want) {
					t.Fatalf("the pass dropped the live removal %s", want.Path)
				}
			}
			if got := slices.ContainsFunc(ledger, func(r enterprisepolicy.ForeignHookRemoval) bool { return r.Path == hook }); got != tc.removed {
				t.Fatalf("recorded removal of %s: %t, want %t", hook, got, tc.removed)
			}
			var incomplete []enterprisepolicy.ForeignHookRemoval
			for _, entry := range ledger {
				if entry.Path == enterprisepolicy.ForeignHookCleanupIncompletePath {
					incomplete = append(incomplete, entry)
				}
			}
			if !tc.incomplete {
				if len(incomplete) != 0 {
					t.Fatalf("a cleanup that knows what it changed left incomplete-cleanup removals %+v", incomplete)
				}
			} else {
				if len(incomplete) != 1 || incomplete[0].Connector != "cursor" {
					t.Fatalf("incomplete cleanup removals %+v", incomplete)
				}
				parts := strings.Split(incomplete[0].Mark, ":")
				end, _ := strconv.ParseInt(parts[len(parts)-1], 10, 64)
				newAgent := fmt.Sprintf("%s:%s:4444:%d", goos, boot, end+1)
				if got := foreignTxCall(t, ledger, "4242", "cursor", oldAgent); !got.Deny {
					t.Fatalf("a cursor agent that started before an uncertain cleanup was allowed: %+v", got)
				}
				for _, agent := range []string{oldAgent, newAgent} {
					if got := foreignTxCall(t, ledger, "4242", "codex", agent); got.Deny {
						t.Fatalf("a codex agent, which loads no file the cleanup planned, is denied: %+v", got)
					}
				}
				if got := foreignTxCall(t, ledger, "4242", "cursor", newAgent); got.Deny {
					t.Fatalf("a cursor agent started after the cleanup ended (or a new account reusing the uid) is denied: %+v", got)
				}
			}
			if tc.full {
				if got := foreignTxCall(t, ledger, "4242", "cursor", oldAgent); !got.Deny || !strings.Contains(got.Reason, "hooks-0.json") {
					t.Fatalf("the old agent's first call after the pass: %+v", got)
				}
			}
		})
	}
}

// A routine pass that finds nothing to remove publishes no denial: while
// its worker runs, and after it, the account's running agents keep
// working, and no second worker runs. The in-process cleanup (Windows, and
// Unix per-user rows) follows the same rule.
func TestForeignHookNoOpCleanupDeniesNoAgent(t *testing.T) {
	goos, boot, start := foreignTxClock(t)
	agent := fmt.Sprintf("%s:%s:4343:%d", goos, boot, start)
	t.Run("worker pass", func(t *testing.T) {
		var dataDir string
		workers := 0
		dataDir = useForeignTxPass(t, func(request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
			workers++
			if !foreignTxPlanning(request) {
				t.Errorf("a pass with nothing to remove ran a cleaning worker: %+v", request.ForeignCleanup)
			}
			entries, err := loadEnterpriseForeignHookRemovals(foreignTxLedger(dataDir))
			if err != nil {
				t.Errorf("ledger: %v", err)
			}
			for _, name := range []string{"cursor", "codex"} {
				if got := foreignTxCall(t, entries, "4242", name, agent); got.Deny {
					t.Errorf("a %s call during a pass that removes nothing was denied: %+v", name, got)
				}
			}
			return foreignTxPlan(map[string][]string{"cursor": nil}), nil
		})
		log := runForeignTxPass(t)
		if workers != 1 {
			t.Fatalf("%d workers ran for a pass with nothing to remove; log:\n%s", workers, log)
		}
		if _, err := os.Lstat(foreignTxLedger(dataDir)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a pass that removes nothing wrote the removal ledger (%v); log:\n%s", err, log)
		}
	})
	t.Run("a pass denies only the connectors that load a planned file", func(t *testing.T) {
		var dataDir string
		dataDir = useForeignTxPass(t, func(request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
			if foreignTxPlanning(request) {
				return foreignTxPlan(map[string][]string{"cursor": {"/home/alice/.cursor/hooks.json"}}), nil
			}
			entries, _ := loadEnterpriseForeignHookRemovals(foreignTxLedger(dataDir))
			if got := foreignTxCall(t, entries, "4242", "cursor", agent); !got.Deny {
				t.Errorf("a cursor call during the removal of a cursor hook was allowed: %+v", got)
			}
			if got := foreignTxCall(t, entries, "4242", "codex", agent); got.Deny {
				t.Errorf("a codex call during the removal of a cursor-only hook was denied: %+v", got)
			}
			return enterpriseHookWorkerResponse{Cleanup: map[string]enterpriseHookWorkerCleanupReport{"cursor": {}}}, nil
		})
		runForeignTxPass(t)
	})
	t.Run("in-process cleanup", func(t *testing.T) {
		resetForeignTxs(t)
		dataDir := useUserCleanupStateDir(t)
		previous, previousRunAs := cfg, enterpriseForeignHookRunAsTarget
		t.Cleanup(func() { cfg, enterpriseForeignHookRunAsTarget = previous, previousRunAs })
		cfg = standaloneTestConfig(dataDir)
		cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"cursor": {}, "codex": {}}
		home := t.TempDir()
		var during []string
		enterpriseForeignHookRunAsTarget = func(_ enterprisehooks.TargetCredentials, fn func() error) error {
			entries, _ := loadEnterpriseForeignHookRemovals(foreignTxLedger(dataDir))
			connectors := []string{}
			for _, entry := range foreignTxPending(entries) {
				connectors = append(connectors, entry.Connector)
			}
			during = append(during, strings.Join(connectors, ","))
			return fn()
		}
		target := enterprisehooks.TargetCredentials{UserHome: home, UID: 4242, GID: 4242}
		if _, err := enterpriseForeignHookCleanup(target, "cursor", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(foreignTxLedger(dataDir)); !errors.Is(err, os.ErrNotExist) || !slices.Equal(during, []string{""}) {
			t.Fatalf("an in-process cleanup with nothing to remove published a denial: runs %q, ledger %v", during, err)
		}
		hooks := filepath.Join(home, ".cursor", "hooks.json")
		if err := os.MkdirAll(filepath.Dir(hooks), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(hooks, []byte(`{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		during = nil
		result, err := enterpriseForeignHookCleanup(target, "cursor", "")
		if err != nil || len(result.Removed) != 1 {
			t.Fatalf("cleanup: %+v %v", result, err)
		}
		ledger := readForeignTxLedger(t, dataDir)
		if !slices.Equal(during, []string{"", "cursor"}) || len(foreignTxPending(ledger)) != 0 ||
			!slices.ContainsFunc(ledger, func(r enterprisepolicy.ForeignHookRemoval) bool { return r.Path == hooks && r.Connector == "cursor" }) {
			t.Fatalf("the cleanup must plan without a denial, then clean under a cursor denial and record the removal: runs %q, ledger %+v", during, ledger)
		}
	})
}

// The denial names every connector whose agent may load a planned file:
// Cursor also loads Claude Code's user settings.
func TestForeignHookDenialCoversEveryConnectorThatLoadsAPlannedFile(t *testing.T) {
	previous := cfg
	t.Cleanup(func() { cfg = previous })
	cfg = standaloneTestConfig(t.TempDir())
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"claudecode": {}, "cursor": {}, "codex": {}}
	got := enterpriseForeignHookDenialConnectors("/home/alice", map[string][]string{"claudecode": {"/home/alice/.claude/settings.json"}})
	if !slices.Equal(got, []string{"claudecode", "cursor"}) {
		t.Fatalf("denial connectors %v", got)
	}
	if got := enterpriseForeignHookDenialConnectors("/home/alice", map[string][]string{"cursor": nil}); len(got) != 0 {
		t.Fatalf("a cleanup with no planned file denies %v", got)
	}
	if _, err := beginEnterpriseForeignHookCleanup(io.Discard, "1000", nil); err == nil {
		t.Fatal("a cleanup opened a transaction without a connector to deny")
	}
}

// A cleaning worker that never started (its executable could not be found
// or started, or the guardian refused it) edited nothing: its transaction
// clears its pending denial and leaves no incomplete-cleanup removal, so
// running agents are not denied for the removal TTL. A worker that started
// and then failed stays uncertain.
func TestForeignHookWorkerThatNeverStartedLeavesNoDenial(t *testing.T) {
	notExecutable := filepath.Join(t.TempDir(), "defenseclaw")
	if err := os.WriteFile(notExecutable, []byte("not a program"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		executable func() (string, error)
		incomplete bool
	}{
		{name: "executable lookup failed", executable: func() (string, error) { return "", errors.New("readlink /proc/self/exe: no such file") }},
		{name: "executable missing", executable: func() (string, error) { return filepath.Join(t.TempDir(), "gone"), nil }},
		{name: "executable cannot run", executable: func() (string, error) { return notExecutable, nil }},
		{name: "worker started and failed", executable: func() (string, error) { return "/bin/false", nil }, incomplete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("runs the worker as the test's own non-root account")
			}
			goos, boot, start := foreignTxClock(t)
			oldAgent := fmt.Sprintf("%s:%s:4343:%d", goos, boot, start)
			previousExe := enterpriseHookWorkerExecutable
			t.Cleanup(func() { enterpriseHookWorkerExecutable = previousExe })
			var workerErr error
			dataDir := useForeignTxPass(t, func(request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				if foreignTxPlanning(request) {
					return foreignTxPlan(map[string][]string{"cursor": {"/home/alice/.cursor/hooks.json"}}), nil
				}
				// The real worker launch, as the test's own account.
				enterpriseHookWorkerExecutable = tc.executable
				response, err := runEnterpriseHookWorker(context.Background(), enterpriseHookWorkerAccount{
					UID: os.Getuid(), GID: os.Getgid(), User: "self", Home: t.TempDir()}, request)
				workerErr = err
				return response, err
			})
			log := runForeignTxPass(t)
			if workerErr == nil || errors.Is(workerErr, errEnterpriseHookWorkerNotStarted) == tc.incomplete {
				t.Fatalf("worker error %v; not-started %t, want %t", workerErr, errors.Is(workerErr, errEnterpriseHookWorkerNotStarted), !tc.incomplete)
			}
			ledger := readForeignTxLedger(t, dataDir)
			if pending := foreignTxPending(ledger); len(pending) != 0 || len(enterpriseForeignHookCleanupTxs) != 0 {
				t.Fatalf("the pass left pending denials %+v; log:\n%s", pending, log)
			}
			incomplete := slices.ContainsFunc(ledger, func(r enterprisepolicy.ForeignHookRemoval) bool {
				return r.Path == enterprisepolicy.ForeignHookCleanupIncompletePath
			})
			if incomplete != tc.incomplete {
				t.Fatalf("incomplete-cleanup removal %t, want %t: %+v", incomplete, tc.incomplete, ledger)
			}
			if got := foreignTxCall(t, ledger, "4242", "cursor", oldAgent); got.Deny != tc.incomplete {
				t.Fatalf("a running cursor agent after the pass: deny %t, want %t: %+v", got.Deny, tc.incomplete, got)
			}
		})
	}
	t.Run("refused before the worker", func(t *testing.T) {
		workers := 0
		dataDir := useForeignTxPass(t, func(request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
			workers++
			if foreignTxPlanning(request) {
				return foreignTxPlan(map[string][]string{"cursor": {"/home/alice/.cursor/hooks.json"}}), nil
			}
			return enterpriseHookWorkerResponse{}, nil
		})
		// The ledger cannot be read, so the denial cannot be published.
		writeForeignTxLedger(t, dataDir, nil)
		if err := os.WriteFile(foreignTxLedger(dataDir), []byte("{"), 0o640); err != nil {
			t.Fatal(err)
		}
		log := runForeignTxPass(t)
		if workers != 1 || !strings.Contains(log, "refused before file removal") {
			t.Fatalf("a cleanup whose denial could not be published ran %d workers; log:\n%s", workers, log)
		}
	})
}

// A ledger that cannot be read (it does not parse, or fails its trust
// check) is never replaced: the gateway keeps denying every call until it
// can be read again or an administrator removes it, and once it can be read
// its removals still deny the agents that started before them. No ledger
// update replaces it: a pass's reconcile, a pass that removes nothing, a
// cleanup's start or the recording of a removal.
func TestForeignHookUnreadableLedgerIsKept(t *testing.T) {
	for _, damage := range []string{"does not parse", "fails its trust check"} {
		t.Run(damage, func(t *testing.T) {
			goos, boot, start := foreignTxClock(t)
			oldAgent := fmt.Sprintf("%s:%s:4343:%d", goos, boot, start)
			dataDir := useForeignTxPass(t, func(enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				return foreignTxPlan(nil), nil
			})
			ledger := foreignTxLedger(dataDir)
			removal := enterprisepolicy.ForeignHookRemoval{Identity: "4242", Connector: "cursor", Path: "/home/alice/.cursor/hooks.json",
				At: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), Mark: fmt.Sprintf("%s:%s:%d", goos, boot, start+1)}
			writeForeignTxLedger(t, dataDir, []enterprisepolicy.ForeignHookRemoval{removal})
			good, err := os.ReadFile(ledger)
			if err != nil {
				t.Fatal(err)
			}
			var restore func()
			if damage == "does not parse" {
				if err := os.WriteFile(ledger, []byte(`{"version": 1, "removals": [`), 0o640); err != nil {
					t.Fatal(err)
				}
				restore = func() {
					if err := os.WriteFile(ledger, good, 0o640); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				trust := enterpriseHookAuthorizationFileTrustCheck
				enterpriseHookAuthorizationFileTrustCheck = func(path string) error {
					if filepath.Base(path) == enterprisepolicy.ForeignHookRemovalsFile {
						return errors.New("group-writable")
					}
					return trust(path)
				}
				restore = func() { enterpriseHookAuthorizationFileTrustCheck = trust }
				t.Cleanup(restore)
			}
			damaged, err := os.ReadFile(ledger)
			if err != nil {
				t.Fatal(err)
			}
			reconcileEnterpriseForeignHookCleanups(io.Discard)
			log := runForeignTxPass(t)
			if _, err := beginEnterpriseForeignHookCleanup(io.Discard, "4242", []string{"cursor"}); err == nil || len(enterpriseForeignHookCleanupTxs) != 0 {
				t.Errorf("a cleanup started on an unreadable ledger (%v) or left transactions %v", err, enterpriseForeignHookCleanupTxs)
			}
			if err := recordEnterpriseForeignHookRemovals(io.Discard, "4242", "/home/alice", "cursor", []string{"/home/alice/.cursor/other.json"}); err == nil {
				t.Error("a removal was recorded into a replaced ledger")
			}
			if data, err := os.ReadFile(ledger); err != nil || string(data) != string(damaged) {
				t.Fatalf("the unreadable ledger was replaced (%v):\n%s\nlog:\n%s", err, data, log)
			}
			if _, err := loadEnterpriseForeignHookRemovals(ledger); err == nil {
				t.Fatal("the damaged ledger reads; the gateway would not deny")
			}
			restore()
			if got := foreignTxCall(t, readForeignTxLedger(t, dataDir), "4242", "cursor", oldAgent); !got.Deny {
				t.Fatalf("once the ledger can be read again, the agent that started before its removal is allowed: %+v", got)
			}
		})
	}
}

// A cleanup whose pending denial cannot all be published publishes none of
// it and cleans nothing.
func TestForeignHookCleanupDenialIsPublishedWhole(t *testing.T) {
	resetForeignTxs(t)
	dataDir := useUserCleanupStateDir(t)
	previous := cfg
	t.Cleanup(func() { cfg = previous })
	cfg = standaloneTestConfig(dataDir)
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"cursor": {}, "codex": {}}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var fixture []enterprisepolicy.ForeignHookRemoval
	// Other cleanups' denials with no owner stay; they leave one slot of
	// the cleanup budget (4096 entries).
	for i := 0; i < 4095; i++ {
		fixture = append(fixture, enterprisepolicy.ForeignHookRemoval{Identity: "1000", Connector: "cursor",
			Path: enterprisepolicy.ForeignHookCleanupPendingPath(strconv.Itoa(i), ""), At: now, Mark: "m"})
	}
	writeForeignTxLedger(t, dataDir, fixture)
	if _, err := beginEnterpriseForeignHookCleanup(io.Discard, "1000", []string{"cursor", "codex"}); err == nil {
		t.Fatal("a cleanup started without its whole denial")
	}
	if got := readForeignTxLedger(t, dataDir); len(got) != len(fixture) {
		t.Fatalf("a refused cleanup published part of its denial: %d entries, want %d", len(got), len(fixture))
	}
	if len(enterpriseForeignHookCleanupTxs) != 0 {
		t.Fatalf("a refused cleanup left a transaction: %v", enterpriseForeignHookCleanupTxs)
	}
}

// A transaction whose end cannot be written keeps its pending denial, and
// the next ledger update (here the next pass's reconcile) settles it.
func TestForeignHookCleanupEndIsRetried(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(strconv.FormatBool(uncertain), func(t *testing.T) {
			resetForeignTxs(t)
			dataDir := useUserCleanupStateDir(t)
			previous := cfg
			t.Cleanup(func() { cfg = previous })
			cfg = standaloneTestConfig(dataDir)
			cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"cursor": {}}
			token, err := beginEnterpriseForeignHookCleanup(io.Discard, "1000", []string{"cursor"})
			if err != nil {
				t.Fatal(err)
			}
			setter := enterpriseHookAuthorizationOwnershipSetter
			enterpriseHookAuthorizationOwnershipSetter = func(string) error { return errors.New("chown: transient") }
			err = finishEnterpriseForeignHookCleanup(io.Discard, token, uncertain)
			enterpriseHookAuthorizationOwnershipSetter = setter
			if err == nil {
				t.Fatal("the failing end reported success")
			}
			if pending := foreignTxPending(readForeignTxLedger(t, dataDir)); len(pending) == 0 {
				t.Fatal("a failed end dropped the pending denial")
			}
			reconcileEnterpriseForeignHookCleanups(io.Discard)
			ledger := readForeignTxLedger(t, dataDir)
			if pending := foreignTxPending(ledger); len(pending) != 0 || len(enterpriseForeignHookCleanupTxs) != 0 {
				t.Fatalf("the retry did not settle the transaction: %+v", ledger)
			}
			if got := slices.ContainsFunc(ledger, func(r enterprisepolicy.ForeignHookRemoval) bool {
				return r.Path == enterprisepolicy.ForeignHookCleanupIncompletePath
			}); got != uncertain {
				t.Fatalf("incomplete-cleanup removal %t after an end with uncertain=%t: %+v", got, uncertain, ledger)
			}
		})
	}
}

// The pending denial of a guardian that died mid-cleanup is settled once
// no worker of it can still run, as an incomplete cleanup: a new account
// that reuses the uid is not denied forever. A denial whose cleanup may
// still run stays, up to the longest a cleanup can hold it whoever owns it.
func TestForeignHookAbandonedCleanupDenialIsSettled(t *testing.T) {
	const deadOwner = "linux:boot:999999:1"
	for _, tc := range []struct {
		name    string
		owner   string
		age     time.Duration
		ended   bool
		settled bool
	}{
		{name: "dead owner, workers gone", owner: deadOwner, age: 11 * time.Minute, ended: true, settled: true},
		{name: "owner still running", owner: deadOwner, age: 30 * time.Minute, ended: false},
		{name: "a worker may still run", owner: deadOwner, age: 9 * time.Minute, ended: true},
		{name: "unknown owner, a cleanup may still run", owner: "", age: 59 * time.Minute, ended: true},
		// No cleanup holds its denial this long: a denial whose owner
		// cannot be shown to have ended is settled, never kept forever.
		{name: "unknown owner, past every cleanup", owner: "", age: 61 * time.Minute, settled: true},
		{name: "malformed owner, past every cleanup", owner: "linux:boot:x", age: 61 * time.Minute, settled: true},
		{name: "owner not shown to have ended, past every cleanup", owner: deadOwner, age: 61 * time.Minute, ended: false, settled: true},
		{name: "this process, no cleanup of it runs, recent", owner: "self", age: 30 * time.Minute},
		{name: "this process, no cleanup of it runs, past every cleanup", owner: "self", age: 61 * time.Minute, settled: true},
		{name: "dated past the bound ahead (clock set back)", owner: "", age: -61 * time.Minute, settled: true},
		{name: "dated a little ahead", owner: "", age: -time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			goos, boot, start := foreignTxClock(t)
			resetForeignTxs(t)
			dataDir := useUserCleanupStateDir(t)
			previous, previousEnded := cfg, enterpriseForeignHookOwnerEnded
			t.Cleanup(func() { cfg, enterpriseForeignHookOwnerEnded = previous, previousEnded })
			cfg = standaloneTestConfig(dataDir)
			enterpriseForeignHookOwnerEnded = func(owner string) bool { return owner == deadOwner && tc.ended }
			at := time.Now().UTC().Add(-tc.age).Format(time.RFC3339Nano)
			owner := tc.owner
			if owner == "self" {
				owner = enterpriseForeignHookCleanupOwner()
			}
			path := enterprisepolicy.ForeignHookCleanupPendingPath("0123456789abcdef", owner)
			writeForeignTxLedger(t, dataDir, []enterprisepolicy.ForeignHookRemoval{
				{Identity: "1000", Connector: "cursor", Path: path, At: at, Mark: "m"},
				{Identity: "1000", Connector: "codex", Path: path, At: at, Mark: "m"},
			})
			reconcileEnterpriseForeignHookCleanups(io.Discard)
			ledger := readForeignTxLedger(t, dataDir)
			if got := len(foreignTxPending(ledger)) == 0; got != tc.settled {
				t.Fatalf("settled %t, want %t: %+v", got, tc.settled, ledger)
			}
			if !tc.settled {
				return
			}
			if len(ledger) != 2 || ledger[0].Path != enterprisepolicy.ForeignHookCleanupIncompletePath {
				t.Fatalf("an abandoned cleanup did not become an incomplete-cleanup removal: %+v", ledger)
			}
			parts := strings.Split(ledger[0].Mark, ":")
			end, _ := strconv.ParseInt(parts[len(parts)-1], 10, 64)
			if got := foreignTxCall(t, ledger, "1000", "cursor", fmt.Sprintf("%s:%s:4343:%d", goos, boot, start)); !got.Deny {
				t.Fatalf("an agent that ran during the abandoned cleanup was allowed: %+v", got)
			}
			if got := foreignTxCall(t, ledger, "1000", "codex", fmt.Sprintf("%s:%s:4444:%d", goos, boot, end+1)); got.Deny {
				t.Fatalf("a new agent of the account (or of an account reusing the uid) is denied: %+v", got)
			}
		})
	}
}

// The two-worker pass with real worker processes: a clean home runs one
// worker and writes no ledger; a home with a foreign Cursor hook gets a
// planning worker and a cleaning worker, and the removal is recorded with
// no pending denial left.
func TestForeignHookCleanupPassWithRealWorkers(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "real")
	home := t.TempDir()
	var dataDir string
	workers := 0
	dataDir = useForeignTxPass(t, nil)
	self := enterprisehooks.UnixEligibleAccount{User: "self", UID: os.Getuid(), GID: os.Getgid(), Home: home}
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{self}, nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		workers++
		return runEnterpriseHookWorker(ctx, account, request)
	}
	pass := func() string {
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		var log bytes.Buffer
		runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Now(), enterprisehooks.Manifest{}, nil, "")
		return log.String()
	}
	if log := pass(); workers != 1 {
		t.Fatalf("a clean home ran %d workers; log:\n%s", workers, log)
	}
	if _, err := os.Lstat(foreignTxLedger(dataDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a pass over a clean home wrote the removal ledger: %v", err)
	}
	hooks := filepath.Join(home, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooks), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooks, []byte(`{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	workers = 0
	log := pass()
	if data, _ := os.ReadFile(hooks); workers != 2 || strings.Contains(string(data), "rewrite.sh") {
		t.Fatalf("%d workers; the foreign hook must be removed: %s\nlog:\n%s", workers, data, log)
	}
	ledger := readForeignTxLedger(t, dataDir)
	if len(foreignTxPending(ledger)) != 0 || !slices.ContainsFunc(ledger, func(r enterprisepolicy.ForeignHookRemoval) bool {
		return r.Path == hooks && r.Connector == "cursor" && r.Identity == strconv.Itoa(os.Getuid())
	}) {
		t.Fatalf("the removal must be recorded and no pending denial left: %+v\nlog:\n%s", ledger, log)
	}
}

// useForeignTxLedgerWrites sets up a standalone guardian with Cursor
// governed whose ledger writes report what the gateway could see: problem
// is called when the owner is set on the published ledger, or when the
// published ledger is in a state the gateway cannot read (mode not 0640)
// while a write sets the owner of or checks a file. It returns the ledger.
func useForeignTxLedgerWrites(t *testing.T, problem func(string)) string {
	t.Helper()
	resetForeignTxs(t)
	dataDir := useUserCleanupStateDir(t)
	previous := cfg
	setter, trust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationFileTrustCheck
	t.Cleanup(func() {
		cfg = previous
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationFileTrustCheck = setter, trust
	})
	cfg = standaloneTestConfig(dataDir)
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"cursor": {}}
	ledger := foreignTxLedger(dataDir)
	readable := func(stage string) {
		info, err := os.Lstat(ledger)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil || info.Mode().Perm() != 0o640 {
			problem(fmt.Sprintf("%s: the published ledger is %v (%v)", stage, info.Mode(), err))
		}
	}
	enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
		if path == ledger {
			problem("the owner was set on the published ledger")
		}
		readable("owner")
		return setter(path)
	}
	enterpriseHookAuthorizationFileTrustCheck = func(path string) error {
		readable("trust check")
		return trust(path)
	}
	return ledger
}

// foreignTxLedgerLeftovers names the files a ledger write left next to the
// ledger.
func foreignTxLedgerLeftovers(t *testing.T, ledger string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(ledger))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if entry.Name() != filepath.Base(ledger) && strings.Contains(entry.Name(), enterprisepolicy.ForeignHookRemovalsFile) {
			names = append(names, entry.Name())
		}
	}
	return names
}

// The gateway reads the removal ledger on every call and denies every
// account while it cannot read it. So every ledger write (a cleanup's
// start, a recorded removal, a settle, an uncertain settle, a reconcile)
// publishes a file that already has its final mode and owner and passed
// its trust check. A ledger published 0600 and opened up only after its
// rename denied clean accounts for that moment, and pending denials and
// their settlement made such writes frequent.
func TestForeignHookLedgerIsGatewayReadableAtEveryWrite(t *testing.T) {
	var problems []string
	ledger := useForeignTxLedgerWrites(t, func(problem string) { problems = append(problems, problem) })
	token, err := beginEnterpriseForeignHookCleanup(io.Discard, "1000", []string{"cursor"})
	if err != nil {
		t.Fatal(err)
	}
	if err := recordEnterpriseForeignHookRemovals(io.Discard, "1000", "/home/u", "cursor", []string{"/home/u/.cursor/hooks.json"}); err != nil {
		t.Fatal(err)
	}
	if err := finishEnterpriseForeignHookCleanup(io.Discard, token, false); err != nil {
		t.Fatal(err)
	}
	if token, err = beginEnterpriseForeignHookCleanup(io.Discard, "1001", []string{"cursor"}); err != nil {
		t.Fatal(err)
	}
	if err := finishEnterpriseForeignHookCleanup(io.Discard, token, true); err != nil {
		t.Fatal(err)
	}
	reconcileEnterpriseForeignHookCleanups(io.Discard)
	if len(problems) != 0 {
		t.Fatalf("the gateway could meet a ledger it cannot read:\n%s", strings.Join(problems, "\n"))
	}
	info, err := os.Lstat(ledger)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("the published ledger is %v (%v), want 0640", info.Mode(), err)
	}
	if leftovers := foreignTxLedgerLeftovers(t, ledger); len(leftovers) != 0 {
		t.Fatalf("ledger writes left %v", leftovers)
	}
	if _, err := loadEnterpriseForeignHookRemovals(ledger); err != nil {
		t.Fatalf("the published ledger does not read: %v", err)
	}
}

// A ledger write whose new file cannot be given its owner, has the wrong
// mode or fails its trust check publishes nothing: the ledger the gateway
// reads stays as it was, readable, and the cleanup does not start.
func TestForeignHookLedgerWriteThatCannotBeProtectedPublishesNothing(t *testing.T) {
	for _, failure := range []string{"owner", "mode", "trust check"} {
		t.Run(failure, func(t *testing.T) {
			ledger := useForeignTxLedgerWrites(t, func(problem string) { t.Error(problem) })
			if _, err := beginEnterpriseForeignHookCleanup(io.Discard, "1000", []string{"cursor"}); err != nil {
				t.Fatal(err)
			}
			good, err := os.ReadFile(ledger)
			if err != nil {
				t.Fatal(err)
			}
			setter, trust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationFileTrustCheck
			// newLedger is the file a ledger write publishes, before it does.
			newLedger := func(path string) bool {
				return path != ledger && filepath.Dir(path) == filepath.Dir(ledger) && strings.Contains(filepath.Base(path), enterprisepolicy.ForeignHookRemovalsFile)
			}
			switch failure {
			case "owner":
				enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
					if newLedger(path) {
						return errors.New("chown: no such group")
					}
					return setter(path)
				}
			case "mode":
				enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
					if err := setter(path); err != nil {
						return err
					}
					if !newLedger(path) {
						return nil
					}
					return os.Chmod(path, 0o600)
				}
			case "trust check":
				enterpriseHookAuthorizationFileTrustCheck = func(path string) error {
					if newLedger(path) {
						return errors.New("group-writable")
					}
					return trust(path)
				}
			}
			_, err = beginEnterpriseForeignHookCleanup(io.Discard, "1001", []string{"cursor"})
			enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationFileTrustCheck = setter, trust
			if err == nil {
				t.Fatal("a cleanup started on a ledger write that could not be protected")
			}
			if data, err := os.ReadFile(ledger); err != nil || string(data) != string(good) {
				t.Fatalf("a write that could not be protected changed the ledger (%v)", err)
			}
			if info, err := os.Lstat(ledger); err != nil || info.Mode().Perm() != 0o640 {
				t.Fatalf("the ledger is %v (%v) after a refused write, want 0640", info.Mode(), err)
			}
			if leftovers := foreignTxLedgerLeftovers(t, ledger); len(leftovers) != 0 {
				t.Fatalf("a refused write left %v", leftovers)
			}
			if got := len(enterpriseForeignHookCleanupTxs); got != 1 {
				t.Fatalf("%d transactions open, want only the first cleanup's", got)
			}
		})
	}
}
