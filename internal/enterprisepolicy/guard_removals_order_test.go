// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
)

// A cleanup of a file can publish after a later cleanup of the same file
// (it stalled before the ledger lock), a ledger an earlier build wrote dates
// each entry at its publication, and the wall clock can step back between
// two cleanups. The ledger keeps the removal of the cleanup that ended last
// in each case, so an agent process that started between two cleanups, and
// may have loaded the hook the later one removed, stays denied.
func TestForeignHookRemovalLedgerKeepsTheCleanupThatEndedLast(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	entry := func(mark string, at time.Time) ForeignHookRemoval {
		return ForeignHookRemoval{
			Identity: "1001", Connector: "claudecode", Path: "/home/alice/.claude/settings.json",
			At: at.Format(time.RFC3339Nano), Mark: mark,
		}
	}
	this := runtime.GOOS + ":b:"
	older := entry(this+"1000", now.Add(-2*time.Second))
	newer := entry(this+"2000", now.Add(-time.Second))
	// Dated at its publication, after the later cleanup's.
	olderPublishedLast := entry(this+"1000", now.Add(-500*time.Millisecond))
	// The wall clock stepped back between the two cleanups.
	newerAfterClockStep := entry(this+"2000", now.Add(-3*time.Second))
	sameTickEarlier := entry(this+"2000", now.Add(-time.Second-50*time.Millisecond))
	previousBoot := entry(runtime.GOOS+":a:900000", now.Add(-time.Hour))
	thisBoot := entry(this+"10", now.Add(-time.Second))
	cases := []struct {
		name              string
		existing, added   []ForeignHookRemoval
		want              ForeignHookRemoval
		deniesStartedAtOf string
	}{
		{"an older cleanup published last", []ForeignHookRemoval{newer}, []ForeignHookRemoval{olderPublishedLast}, newer, this + "1:1500"},
		{"an older cleanup in the same publication", nil, []ForeignHookRemoval{newer, olderPublishedLast}, newer, this + "1:1500"},
		{"a newer cleanup after the wall clock stepped back", []ForeignHookRemoval{older}, []ForeignHookRemoval{newerAfterClockStep}, newerAfterClockStep, this + "1:1500"},
		{"a newer cleanup published last", []ForeignHookRemoval{older}, []ForeignHookRemoval{newer}, newer, this + "1:1500"},
		{"two cleanups in one clock tick", []ForeignHookRemoval{newer}, []ForeignHookRemoval{sameTickEarlier}, newer, this + "1:2000"},
		{"a cleanup after a reboot", []ForeignHookRemoval{previousBoot}, []ForeignHookRemoval{thisBoot}, thisBoot, this + "1:5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := EncodeForeignHookRemovals(tc.existing, tc.added, now)
			if err != nil {
				t.Fatal(err)
			}
			removals, err := ParseForeignHookRemovals(data)
			if err != nil {
				t.Fatal(err)
			}
			if len(removals) != 1 || removals[0] != tc.want {
				t.Fatalf("the ledger must keep the removal of the cleanup that ended last, %+v: %+v", tc.want, removals)
			}
			if !agentprocess.StartedBefore(tc.deniesStartedAtOf, removals[0].Mark) {
				t.Fatalf("an agent process %s that started before the last cleanup is allowed: %+v", tc.deniesStartedAtOf, removals[0])
			}
		})
	}
}
