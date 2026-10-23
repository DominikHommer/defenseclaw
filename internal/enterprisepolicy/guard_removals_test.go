// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// liveRemovals returns the removals (not pending denials) in data.
func liveRemovals(t *testing.T, data []byte) []ForeignHookRemoval {
	t.Helper()
	parsed, err := ParseForeignHookRemovals(data)
	if err != nil {
		t.Fatal(err)
	}
	return slices.DeleteFunc(parsed, func(r ForeignHookRemoval) bool { return foreignHookCleanupEntry(r.Path) })
}

// Cleanup entries have their own budget: publishing a pending denial,
// ending a cleanup uncertain, and clearing the denial after a cleanup that
// removed nothing must keep exactly the removals the ledger keeps without
// them, whether the entry count or the byte budget limits the ledger.
func TestForeignHookPendingDenialNeverEvictsARemoval(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name  string
		count int
		path  int
	}{
		{name: "entry limit", count: foreignHookRemovalsLimit, path: 40},
		{name: "byte limit", count: 900, path: 1100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var existing []ForeignHookRemoval
			for i := 0; i < tc.count; i++ {
				// The oldest removal is the only one recorded after the
				// old agent (started at 100) started.
				mark, at := runtime.GOOS+":b:50", now.Add(-time.Hour+time.Duration(i)*time.Millisecond)
				if i == 0 {
					mark, at = runtime.GOOS+":b:200", now.Add(-2*time.Hour)
				}
				existing = append(existing, ForeignHookRemoval{Identity: "1000", Connector: "claudecode",
					Path: "/home/u/" + strconv.Itoa(i) + strings.Repeat("x", tc.path), At: at.Format(time.RFC3339Nano), Mark: mark})
			}
			baseline, err := EncodeForeignHookRemovals(existing, nil, now)
			if err != nil {
				t.Fatal(err)
			}
			want := liveRemovals(t, baseline)
			if !slices.ContainsFunc(want, func(r ForeignHookRemoval) bool { return r.Mark == runtime.GOOS+":b:200" }) && tc.name == "entry limit" {
				t.Fatal("fixture: the full ledger must keep the oldest removal")
			}
			var pending []ForeignHookRemoval
			for _, connector := range []string{"claudecode", "codex", "cursor", "copilot", "hermes"} {
				pending = append(pending, ForeignHookRemoval{Identity: "1000", Connector: connector,
					Path: ForeignHookCleanupPendingPath("0123456789abcdef", runtime.GOOS+"::42:7"), At: now.Format(time.RFC3339Nano), Mark: runtime.GOOS + ":b:300"})
				// Another account's cleanup that ended uncertain.
				pending = append(pending, ForeignHookRemoval{Identity: "2000", Connector: connector,
					Path: ForeignHookCleanupIncompletePath, At: now.Format(time.RFC3339Nano), Mark: runtime.GOOS + ":b:300"})
			}
			published, err := EncodeForeignHookRemovals(want, pending, now)
			if err != nil {
				t.Fatalf("a pending denial could not be published next to a full ledger: %v", err)
			}
			if got := liveRemovals(t, published); !slices.Equal(got, want) {
				t.Fatalf("publishing a pending denial changed the removals: kept %d of %d", len(got), len(want))
			}
			parsed, _ := ParseForeignHookRemovals(published)
			if !slices.ContainsFunc(parsed, func(r ForeignHookRemoval) bool { return ForeignHookCleanupPending(r.Path) }) {
				t.Fatal("pending denial missing")
			}
			parsed = slices.DeleteFunc(parsed, func(r ForeignHookRemoval) bool { return ForeignHookCleanupPending(r.Path) })
			cleared, err := EncodeForeignHookRemovals(parsed, nil, now)
			if err != nil {
				t.Fatal(err)
			}
			got := liveRemovals(t, cleared)
			if !slices.Equal(got, want) {
				t.Fatalf("a no-op cleanup changed the removals: kept %d of %d", len(got), len(want))
			}
			if tc.name != "entry limit" {
				return
			}
			// The old agent's first call after the no-op cleanup.
			decision := ApplyForeignHookSession(SessionUpdate{AccountHome: t.TempDir(), StateDir: t.TempDir(),
				Key:      SessionKey{Connector: "claudecode", Session: "s", Process: runtime.GOOS + ":b:4242:100"},
				Removals: got, Now: now})
			if !decision.Deny || !strings.Contains(decision.Reason, "/home/u/0") {
				t.Fatalf("an agent that started before a live removal was allowed after a no-op cleanup: %+v", decision)
			}
		})
	}
}

// Cleanup entries that do not fit their budget fail the whole encoding, so
// a cleanup is refused before it edits anything rather than published in
// part, and never displace a removal.
func TestForeignHookPendingDenialsBeyondTheirBudgetAreRefused(t *testing.T) {
	now := time.Now().UTC()
	var pending []ForeignHookRemoval
	for i := 0; i <= foreignHookCleanupLimit; i++ {
		pending = append(pending, ForeignHookRemoval{Identity: "1000", Connector: "cursor",
			Path: ForeignHookCleanupPendingPath(strconv.Itoa(i), ""), At: now.Format(time.RFC3339Nano), Mark: "m"})
	}
	if _, err := EncodeForeignHookRemovals(nil, pending, now); err == nil {
		t.Fatal("more pending denials than the budget holds were encoded")
	}
	if _, err := EncodeForeignHookRemovals(nil, pending[:foreignHookCleanupLimit], now); err != nil {
		t.Fatalf("a full pending budget must encode: %v", err)
	}
}

func TestForeignHookCleanupPendingPathNamesItsOwner(t *testing.T) {
	path := ForeignHookCleanupPendingPath("0123456789abcdef", "linux:6f1c:4242:99")
	if !ForeignHookCleanupPending(path) || ForeignHookCleanupPendingOwner(path) != "linux:6f1c:4242:99" {
		t.Fatalf("%q", path)
	}
	for _, legacy := range []string{ForeignHookCleanupPendingPrefix + "0123456789abcdef>", "/home/u/.cursor/hooks.json", ForeignHookCleanupIncompletePath} {
		if ForeignHookCleanupPendingOwner(legacy) != "" {
			t.Fatalf("%q names an owner", legacy)
		}
	}
	if ForeignHookCleanupPending(ForeignHookCleanupIncompletePath) {
		t.Fatal("an incomplete-cleanup removal is not pending")
	}
}

// An incomplete cleanup's removal denies agents that started before it,
// like any removal, and lets later ones run.
func TestForeignHookIncompleteCleanupDeniesOnlyEarlierAgents(t *testing.T) {
	now := time.Now().UTC()
	removal := ForeignHookRemoval{Identity: "1000", Connector: "cursor", Path: ForeignHookCleanupIncompletePath,
		At: now.Format(time.RFC3339Nano), Mark: runtime.GOOS + ":b:200"}
	call := func(start int) GuardDecision {
		return ApplyForeignHookSession(SessionUpdate{AccountHome: t.TempDir(), StateDir: t.TempDir(),
			Key:      SessionKey{Connector: "cursor", Session: "s", Process: runtime.GOOS + ":b:4242:" + strconv.Itoa(start)},
			Removals: []ForeignHookRemoval{removal}, Now: now})
	}
	if got := call(100); !got.Deny || !strings.Contains(got.Reason, "did not finish") || !strings.Contains(got.Reason, "restart the agent") {
		t.Fatalf("an agent that started before an incomplete cleanup was not denied: %+v", got)
	}
	if got := call(300); got.Deny {
		t.Fatalf("an agent that started after an incomplete cleanup was denied: %+v", got)
	}
}
