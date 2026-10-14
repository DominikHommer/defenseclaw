//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func rehomedTestUID(t *testing.T, home string) (int, int) {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = 1001, 1001
		if err := os.Chown(home, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	return uid, gid
}

func TestStandaloneCleanupRunsInTrustedCurrentHomeAndEndsRow(t *testing.T) {
	for _, oldPresent := range []bool{false, true} {
		name := "old-missing"
		if oldPresent {
			name = "old-present"
		}
		t.Run(name, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			newHome := f.home(t, "sample-user-new", 0o700)
			uid, gid := rehomedTestUID(t, newHome)
			oldHome := filepath.Join(f.homes, "sample-user-old")
			if oldPresent {
				oldHome = f.home(t, "sample-user-old", 0o755)
			}
			if check := enterpriseHookCheckHome(newHome, uid); check.State != enterprisehooks.HomeAvailable {
				t.Fatalf("current home must be trusted for this test: %+v", check)
			}
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: newHome}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: oldHome, RecordedAt: "2026-10-14T00:00:00Z"}
			wantDataDir := filepath.Join(newHome, ".defenseclaw")
			if !oldPresent {
				entry.DataDir = filepath.Join(oldHome, ".defenseclaw", "moved-state")
				wantDataDir = filepath.Join(newHome, ".defenseclaw", "moved-state")
			}
			originalRunner := enterpriseHookWorkerRunner
			var accounts []enterpriseHookWorkerAccount
			enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				accounts = append(accounts, account)
				return originalRunner(ctx, account, request)
			}
			var attemptLog bytes.Buffer
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &attemptLog, entry, resolver)
			if outcome != enterpriseHookUserCleanupDone || err != nil {
				t.Fatalf("trusted re-home cleanup = %v, %v", outcome, err)
			}
			wantAudit := "the account was re-homed from " + oldHome + " to " + newHome
			if strings.Count(attemptLog.String(), wantAudit) != 1 {
				t.Fatalf("re-home audit line = %q", attemptLog.String())
			}
			if len(accounts) != 1 || accounts[0].UID != uid || accounts[0].Home != newHome {
				t.Fatalf("worker accounts = %+v, want uid %d in %s", accounts, uid, newHome)
			}
			requests := f.requests
			if len(requests) != 1 || requests[0].Operation != enterpriseHookWorkerOpApply || !requests[0].Standalone || len(requests[0].Targets) != 1 {
				t.Fatalf("worker requests = %+v", requests)
			}
			target := requests[0].Targets[0]
			if target.Mode != enterpriseHookWorkerModeRemove || target.Options.ConnectorName != "hermes" ||
				target.Options.UserHome != newHome || target.Options.OwnerUID != uid || target.Options.OwnerGID != gid ||
				target.Options.DataDir != wantDataDir {
				t.Fatalf("cleanup worker target = %+v, want home %s data dir %s uid %d", target, newHome, wantDataDir, uid)
			}
			f.writeManifest(t)
			now := time.Now()
			if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{entry}, now); err != nil {
				t.Fatal(err)
			}
			manifest, err := enterprisehooks.LoadManifest(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			var guardianLog bytes.Buffer
			bindings := enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}
			if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &guardianLog, manifest, bindings, nil, resolver, now); err != nil {
				t.Fatal(err)
			}
			remaining, err := loadEnterpriseHookUserCleanups(f.dataDir)
			if err != nil || len(remaining) != 0 {
				t.Fatalf("cleanup ledger after reconcile = %+v, %v", remaining, err)
			}
			if strings.Count(guardianLog.String(), wantAudit) != 1 || strings.Contains(guardianLog.String(), "no longer enrolled; per-user cleanup done") {
				t.Fatalf("guardian completion audit = %q", guardianLog.String())
			}
			guardianLog.Reset()
			if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &guardianLog, manifest, bindings, nil, resolver, now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if guardianLog.Len() != 0 {
				t.Fatalf("second reconcile repeated the audit: %q", guardianLog.String())
			}
		})
	}
}

func TestStandaloneCleanupLeavesExternalDataDirAsRecorded(t *testing.T) {
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	newHome := f.home(t, "sample-user-new", 0o700)
	uid, gid := rehomedTestUID(t, newHome)
	resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: newHome}
	dataDir := filepath.Join(f.homes, "shared-data")
	entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: filepath.Join(f.homes, "sample-user-old"), DataDir: dataDir}
	if outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver); outcome != enterpriseHookUserCleanupDone || err != nil {
		t.Fatalf("cleanup = %v, %v", outcome, err)
	}
	if got := f.requests[0].Targets[0].Options.DataDir; got != dataDir {
		t.Fatalf("external data dir = %s, want %s", got, dataDir)
	}
}

func TestStandaloneCleanupRefusesUnsafeCurrentHomes(t *testing.T) {
	for _, kind := range []string{"symlink", "other-writable", "group-writable", "wrong-owner", "missing", "relative-no-home", "reserved-no-home", "gone-no-home"} {
		t.Run(kind, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			newHome := f.home(t, "sample-user-new", 0o700)
			uid, gid := rehomedTestUID(t, newHome)
			oldHome := filepath.Join(f.homes, "sample-user-old")
			switch kind {
			case "symlink":
				link := filepath.Join(f.homes, "sample-user-link")
				if err := os.Symlink(newHome, link); err != nil {
					t.Fatal(err)
				}
				newHome = link
			case "other-writable":
				if err := os.Chmod(newHome, 0o777); err != nil {
					t.Fatal(err)
				}
			case "group-writable":
				if err := os.Chmod(newHome, 0o770); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				uid++
			case "missing":
				newHome = filepath.Join(f.homes, "sample-user-missing")
			case "relative-no-home":
				oldHome = f.home(t, "sample-user-old", 0o700)
				newHome = "relative/home"
			case "reserved-no-home":
				oldHome = f.home(t, "sample-user-old", 0o700)
				newHome = "/var/empty"
			case "gone-no-home":
				newHome = "/nonexistent"
			}
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: newHome}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: oldHome}
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver)
			if len(f.requests) != 0 {
				t.Fatalf("unsafe or no-home account ran a worker: %+v", f.requests)
			}
			switch kind {
			case "gone-no-home":
				if outcome != enterpriseHookUserCleanupDone || !errors.Is(err, errEnterpriseHookCleanupHomeGone) {
					t.Fatalf("gone/no-home cleanup = %v, %v", outcome, err)
				}
			case "relative-no-home", "reserved-no-home":
				var kept *enterpriseHookCleanupHomeKeptError
				if outcome != enterpriseHookUserCleanupFailed || !errors.As(err, &kept) {
					t.Fatalf("kept/no-home cleanup = %v, %v", outcome, err)
				}
			default:
				var changed *enterpriseHookTargetHomeChangedError
				var kept *enterpriseHookCleanupHomeKeptError
				if outcome != enterpriseHookUserCleanupFailed || !errors.As(err, &changed) || errors.As(err, &kept) || errors.Is(err, errEnterpriseHookCleanupHomeGone) ||
					!strings.Contains(err.Error(), oldHome) || !strings.Contains(err.Error(), newHome) ||
					!strings.Contains(err.Error(), "fix the account's home") || !strings.Contains(err.Error(), "remove the account") {
					t.Fatalf("unsafe re-home cleanup = %v, %v", outcome, err)
				}
			}
		})
	}
}

func TestStandaloneCleanupDropsGoneOrReassignedAccountsWithoutWorker(t *testing.T) {
	for _, kind := range []string{"gone", "reassigned"} {
		t.Run(kind, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			newHome := f.home(t, "sample-user-new", 0o700)
			uid, gid := rehomedTestUID(t, newHome)
			if kind == "reassigned" {
				resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid + 1, GID: gid, Home: newHome}
			}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: filepath.Join(f.homes, "sample-user-old")}
			if outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver); outcome != enterpriseHookUserCleanupDone || err != nil {
				t.Fatalf("gone/reassigned cleanup = %v, %v", outcome, err)
			}
			if len(f.requests) != 0 {
				t.Fatalf("gone/reassigned account ran a worker: %+v", f.requests)
			}
		})
	}
}

func TestStandaloneCleanupHandlesEmptyDirectoryHome(t *testing.T) {
	for _, oldPresent := range []bool{false, true} {
		name := "recorded-home-gone"
		if oldPresent {
			name = "recorded-home-kept"
		}
		t.Run(name, func(t *testing.T) {
			uid, gid := os.Getuid()+1, os.Getgid()
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{
				"sample-user": {Name: "sample-user", UID: uid, GID: gid, Home: ""},
			}}
			f := newStandaloneFixture(t, resolver)
			oldHome := filepath.Join(f.homes, "sample-user-old")
			if oldPresent {
				oldHome = f.home(t, "sample-user-old", 0o700)
			}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: oldHome, RecordedAt: "2026-10-14T00:00:00Z"}
			var attemptLog bytes.Buffer
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &attemptLog, entry, resolver)
			if oldPresent {
				var kept *enterpriseHookCleanupHomeKeptError
				if outcome != enterpriseHookUserCleanupFailed || !errors.As(err, &kept) {
					t.Fatalf("empty directory home with kept recorded home = %v, %v", outcome, err)
				}
			} else if outcome != enterpriseHookUserCleanupDone || !errors.Is(err, errEnterpriseHookCleanupHomeGone) ||
				strings.Count(attemptLog.String(), "home gone:") != 1 {
				t.Fatalf("empty directory home with gone recorded home = %v, %v, log %q", outcome, err, attemptLog.String())
			}
			if len(f.requests) != 0 {
				t.Fatalf("an account without a directory home ran a worker: %+v", f.requests)
			}
			f.writeManifest(t)
			now := time.Now()
			if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{entry}, now); err != nil {
				t.Fatal(err)
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			report := enterpriseHooksRemoveAllReport{}
			skip := runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
			if len(report.Pending) != 1 || len(report.Failed) != 0 || report.Removed != 0 {
				t.Fatalf("empty-home remove-all report = %+v", report)
			}
			if oldPresent && skip[uid] != enterpriseHookPurgeSkipKeptHome || !oldPresent && skip[uid] != "" {
				t.Fatalf("empty-home purge skip = %+v", skip)
			}
			manifest, err := enterprisehooks.LoadManifest(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			var guardianLog bytes.Buffer
			if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &guardianLog, manifest,
				enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, resolver, now); err != nil {
				t.Fatal(err)
			}
			remaining, err := loadEnterpriseHookUserCleanups(f.dataDir)
			if err != nil {
				t.Fatal(err)
			}
			if oldPresent {
				if len(remaining) != 1 || !strings.Contains(guardianLog.String(), "will retry") {
					t.Fatalf("kept recorded home was retired: %+v, log %q", remaining, guardianLog.String())
				}
			} else if len(remaining) != 0 || strings.Count(guardianLog.String(), "home gone:") != 1 ||
				strings.Contains(guardianLog.String(), "no longer enrolled; per-user cleanup done") {
				t.Fatalf("gone recorded home was not retired once: %+v, log %q", remaining, guardianLog.String())
			}
			if len(f.requests) != 0 {
				t.Fatalf("empty-home reconcile ran a worker: %+v", f.requests)
			}
		})
	}
}

func TestRemoveAllReportsTrustedRehomeRemovedAndUnsafeRehomeFailed(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		name := "trusted"
		if !trusted {
			name = "untrusted"
		}
		t.Run(name, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			newHome := f.home(t, "sample-user-new", 0o700)
			uid, gid := rehomedTestUID(t, newHome)
			if !trusted {
				if err := os.Chmod(newHome, 0o777); err != nil {
					t.Fatal(err)
				}
			}
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: newHome}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: filepath.Join(f.homes, "sample-user-old"), RecordedAt: "2026-10-14T00:00:00Z"}
			if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{entry}, time.Now()); err != nil {
				t.Fatal(err)
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			report := enterpriseHooksRemoveAllReport{}
			jobs := map[int]*enterpriseHookWorkerJob{uid: {Account: enterpriseHookWorkerAccount{UID: uid, GID: gid, User: "sample-user", Home: newHome}}}
			skip := runEnterpriseHookPendingCleanups(cmd, &report, jobs)
			report.OK = len(report.Failed) == 0
			if trusted {
				if report.Removed != 1 || len(report.Failed) != 0 || len(report.Pending) != 0 || !report.OK || skip[uid] != "" || len(f.requests) != 1 {
					t.Fatalf("trusted re-home remove-all report = %+v, skip = %+v, workers = %+v", report, skip, f.requests)
				}
			} else {
				if report.Removed != 0 || len(report.Failed) != 1 || !strings.HasPrefix(report.Failed[0], "sample-user/hermes: ") ||
					!strings.Contains(report.Failed[0], "fix the account's home") || !strings.Contains(report.Failed[0], "remove the account") ||
					report.OK || skip[uid] != enterpriseHookPurgeSkipFailed || len(f.requests) != 0 {
					t.Fatalf("unsafe re-home remove-all report = %+v, skip = %+v, workers = %+v", report, skip, f.requests)
				}
			}
		})
	}
}
