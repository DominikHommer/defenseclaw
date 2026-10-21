// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"strconv"
	"testing"
	"time"
)

// Review P2 (GAP-0352, loop round 4): one account's many removals must not
// evict another account's only one. Before, a ledger over 1024 entries
// kept the newest of all accounts, so a user's 1024 newer removals dropped
// another account's removal while that account's agent still ran the
// removed hook, and the agent was allowed again. Each account and
// connector keeps its horizon, the entry that denies every process any of
// its entries denies, for as long as its newest entry lives; only accounts
// whose horizons alone overflow the ledger are dropped, and they are
// returned for the guardian to hold.
func TestForeignHookRemovalLedgerKeepsEveryAccountsDenialWhenFull(t *testing.T) {
	now := time.Now()
	at := func(age time.Duration) string { return now.Add(-age).UTC().Format(time.RFC3339) }
	victim := []ForeignHookRemoval{{Identity: "1002", Connector: "copilot", Path: "/home/v/.copilot/hooks/a.json", At: at(3 * time.Hour), Mark: "linux:b:500"}}
	var flood []ForeignHookRemoval
	for i := 0; i < 3000; i++ {
		flood = append(flood, ForeignHookRemoval{Identity: "1001", Connector: []string{"copilot", "codex", "claudecode"}[i%3],
			Path: "/home/a/" + strconv.Itoa(i), At: at(time.Hour), Mark: "linux:b:900"})
	}
	// An earlier wall-clock time with a later mark (the clock was set
	// back): the horizon keeps the latest mark and the newest time.
	flood = append(flood, ForeignHookRemoval{Identity: "1001", Connector: "copilot", Path: "/home/a/late", At: at(5 * time.Hour), Mark: "linux:b:999"})
	data, evicted, err := EncodeForeignHookRemovals(victim, flood, now)
	if err != nil || len(evicted) != 0 {
		t.Fatalf("%v %v", evicted, err)
	}
	removals, err := ParseForeignHookRemovals(data)
	if err != nil {
		t.Fatal(err)
	}
	of := func(identity string) []ForeignHookRemoval {
		var out []ForeignHookRemoval
		for _, removal := range removals {
			if removal.Identity == identity {
				out = append(out, removal)
			}
		}
		return out
	}
	denied := func(identity, connector, process string, when time.Time) bool {
		key := SessionKey{Connector: connector, Session: "s", Process: process}
		return ApplyForeignHookRemovals(GuardDecision{}, key, of(identity), nil, when).Deny
	}
	if !denied("1002", "copilot", "linux:b:42:100", now) {
		t.Fatal("another account's removal must survive the flood")
	}
	if denied("1002", "copilot", "linux:b:43:600", now) {
		t.Fatal("an agent of that account started after its removal stays allowed")
	}
	for _, name := range []string{"copilot", "codex", "claudecode"} {
		if !denied("1001", name, "linux:b:44:800", now) {
			t.Fatalf("the flooding account keeps its own %s denial", name)
		}
	}
	if !denied("1001", "copilot", "linux:b:45:950", now) {
		t.Fatal("the horizon keeps the latest mark of the pair")
	}
	if !denied("1001", "copilot", "linux:b:46:950", now.Add(sessionRecordTTL-90*time.Minute)) {
		t.Fatal("the horizon lives as long as the pair's newest entry")
	}

	// More pairs than the ledger holds: the oldest accounts are dropped
	// and named, never silently.
	var many []ForeignHookRemoval
	for i := 0; i < foreignHookRemovalsLimit+10; i++ {
		many = append(many, ForeignHookRemoval{Identity: strconv.Itoa(5000 + i), Connector: "copilot", Path: "/x",
			At: now.Add(-time.Duration(i) * time.Minute).UTC().Format(time.RFC3339), Mark: "linux:b:900"})
	}
	data, evicted, err = EncodeForeignHookRemovals(nil, many, now)
	if err != nil {
		t.Fatal(err)
	}
	if removals, err = ParseForeignHookRemovals(data); err != nil || len(removals) != foreignHookRemovalsLimit {
		t.Fatalf("%d %v", len(removals), err)
	}
	if len(evicted) != 10 || evicted[0] != strconv.Itoa(5000+foreignHookRemovalsLimit) {
		t.Fatalf("the dropped accounts must be named: %v", evicted)
	}
	for _, identity := range evicted {
		if len(of(identity)) != 0 {
			t.Fatalf("%s is both kept and dropped", identity)
		}
	}
}
