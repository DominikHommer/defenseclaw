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

// Every cleanup transaction of a pass ends: a pending denial never outlives
// its worker, whatever the worker did. A cleanup that cannot tell what it
// changed leaves removals at its end, which deny the account's agents that
// started earlier and let later ones (also a new account that reuses the
// uid) run; a cleanup that removed nothing leaves the ledger as it was, also
// when it is full.
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
		{name: "no-op cleanup on a full ledger", full: true, response: enterpriseHookWorkerResponse{Cleanup: map[string]enterpriseHookWorkerCleanupReport{"cursor": {}}}},
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
			dataDir = useForeignTxPass(t, func(request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				// The denial is published before the worker can edit, for
				// every governed connector.
				entries, _ := loadEnterpriseForeignHookRemovals(foreignTxLedger(dataDir))
				pending := foreignTxPending(entries)
				connectors := []string{}
				for _, entry := range pending {
					if entry.Identity == "4242" {
						connectors = append(connectors, entry.Connector)
					}
				}
				slices.Sort(connectors)
				sawPending = len(request.ForeignCleanup) == 1 && strings.Join(connectors, ",") == "codex,cursor"
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
			if !sawPending {
				t.Fatalf("the worker ran without the account's pending denial; log:\n%s", log)
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
				connectors := []string{}
				for _, entry := range incomplete {
					connectors = append(connectors, entry.Connector)
				}
				slices.Sort(connectors)
				if strings.Join(connectors, ",") != "codex,cursor" {
					t.Fatalf("incomplete cleanup removals %+v", incomplete)
				}
				parts := strings.Split(incomplete[0].Mark, ":")
				end, _ := strconv.ParseInt(parts[len(parts)-1], 10, 64)
				newAgent := fmt.Sprintf("%s:%s:4444:%d", goos, boot, end+1)
				for _, name := range []string{"cursor", "codex"} {
					if got := foreignTxCall(t, ledger, "4242", name, oldAgent); !got.Deny {
						t.Fatalf("a %s agent that started before an uncertain cleanup was allowed: %+v", name, got)
					}
					if got := foreignTxCall(t, ledger, "4242", name, newAgent); got.Deny {
						t.Fatalf("a %s agent started after the cleanup ended (or a new account reusing the uid) is denied: %+v", name, got)
					}
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
	if _, err := beginEnterpriseForeignHookCleanup(io.Discard, "1000", []string{"cursor"}); err == nil {
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
// still run stays.
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
		{name: "owner still running", owner: deadOwner, age: time.Hour, ended: false},
		{name: "a worker may still run", owner: deadOwner, age: 9 * time.Minute, ended: true},
		{name: "unknown owner", owner: "", age: time.Hour, ended: true},
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
			path := enterprisepolicy.ForeignHookCleanupPendingPath("0123456789abcdef", tc.owner)
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
