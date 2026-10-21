// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-1130: at the bound, the identity.observed throttle kept its recent
// users instead of forgetting all of them, and admits a new user once a mark
// ages out.
func TestIdentityObservedThrottleKeepsRecentUsersAtItsBound(t *testing.T) {
	identityObservedState.Lock()
	saved, savedPending := identityObservedState.last, identityObservedState.pending
	identityObservedState.last, identityObservedState.pending = map[string]identityObservedMark{}, map[string]bool{}
	identityObservedState.Unlock()
	t.Cleanup(func() {
		identityObservedState.Lock()
		identityObservedState.last, identityObservedState.pending = saved, savedPending
		identityObservedState.Unlock()
	})
	now := time.Now()
	facts := useridentity.DirectoryFacts{Domain: "corp.example"}
	for i := 0; i < identityObservedMaxUsers; i++ {
		finish, due := identityObservedBegin(fmt.Sprint(i), facts, now)
		if !due {
			t.Fatalf("user %d was not due", i)
		}
		finish(true)
	}
	if _, due := identityObservedBegin("overflow", facts, now.Add(time.Second)); due {
		t.Fatal("a user past the bound was admitted while every mark is recent")
	}
	if _, due := identityObservedBegin("0", facts, now.Add(2*time.Second)); due {
		t.Fatal("a recent user was let out again at the bound")
	}
	finish, due := identityObservedBegin("overflow", facts, now.Add(identityDirectoryTTL))
	if !due {
		t.Fatal("a new user was not admitted after the marks aged out")
	}
	finish(true)
}

// GAP-1128: child-session exclusions stay within the sub-session bound
// while inventory writes keep failing.
func TestSubagentExclusionsStayBoundedAcrossFailedWrites(t *testing.T) {
	r := &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	const agent = "agt-00000000000000a1"
	for i := 0; i < agentIdentityRecorderMaxPending+100; i++ {
		r.markSubagentSession(agent, fmt.Sprintf("child-%d", i))
	}
	if n := len(r.exclusions); n > agentIdentityRecorderMaxPending {
		t.Fatalf("%d exclusions buffered, past the bound %d", n, agentIdentityRecorderMaxPending)
	}
	for round := 0; round < 3; round++ {
		batch, excluded := r.take()
		for i := 0; i < 100; i++ {
			r.markSubagentSession(agent, fmt.Sprintf("child-%d-%d", round, i))
		}
		r.restore(batch, excluded) // the write failed
	}
	if n := len(r.exclusions); n > agentIdentityRecorderMaxPending {
		t.Fatalf("%d exclusions after failed writes, past the bound %d", n, agentIdentityRecorderMaxPending)
	}
	for key := range r.exclusions {
		if _, sub := r.subSessions[key]; !sub {
			t.Fatalf("exclusion %q outlived its sub-session", key)
		}
	}
	if _, kept := r.exclusions[subSessionKey(agent, "child-2-99")]; !kept {
		t.Fatal("the newest child link was lost")
	}
}

// GAP-1141, GAP-1144: on standalone Windows a group shown only by its SID
// still matches the assignment that names it, and the note says so.
func TestUnnamedSIDGroupsNoteAgreesWithSIDMatching(t *testing.T) {
	const team = "S-1-5-21-1-2-3-4100"
	sids := newProfileGroupSIDs([]config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{`CORP\team`}}}},
		func(string) (string, error) { return team, nil }, time.Second)
	subject := &profileSubject{Groups: []string{team}}
	groups := &subjectGroups{sids: sids, list: subject.Groups}
	if !groups.has(`CORP\team`) {
		t.Fatal("the SID-only group does not match the assignment that names it")
	}
	note := unnamedGroupsNote(subject, sids)
	if strings.Contains(note, "cannot match") || !strings.Contains(note, "assignments match groups by SID") {
		t.Fatalf("note = %q; want it to agree with the SID match", note)
	}
	if note := unnamedGroupsNote(subject, nil); !strings.Contains(note, "cannot match") {
		t.Fatalf("note without SID matching = %q", note)
	}
}

// GAP-1142: status names a group as unresolved only until its lookup
// answers, without a hook call in between.
func TestGroupSIDWarningsTakeInAFinishedLookup(t *testing.T) {
	release := make(chan struct{})
	lookup := func(string) (string, error) { <-release; return "S-1-5-21-1-2-3-4200", nil }
	assignments := []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{`CORP\gap1142`}}}}
	sids := newProfileGroupSIDs(assignments, lookup, 10*time.Millisecond)
	if warnings := sids.warnings(assignments); len(warnings) != 1 {
		t.Fatalf("warnings while the lookup runs = %q", warnings)
	}
	sids.mu.Lock()
	call := sids.entries[foldKey(`CORP\gap1142`)].call
	sids.mu.Unlock()
	close(release)
	<-call.done
	if warnings := sids.warnings(assignments); len(warnings) != 0 {
		t.Fatalf("warnings after the lookup answered = %q", warnings)
	}
}

// GAP-1261: lookups a stalled directory holds do not keep a reload from
// resolving a group of this computer.
func TestLocalGroupSIDResolvesWhileDirectoryLookupsStall(t *testing.T) {
	previousDomain := profileGroupLocalDomain
	profileGroupLocalDomain = func() string { return "WS01" }
	stalled := make(chan struct{})
	profileGroupSIDLookups.Lock()
	var keys []string
	for i := 0; len(profileGroupSIDLookups.calls)-profileGroupSIDLookups.local < profileGroupSIDLookupsMax; i++ {
		key := foldKey(fmt.Sprintf(`CORP\stalled-%d`, i))
		profileGroupSIDLookups.calls[key] = &profileGroupSIDLookupCall{done: stalled}
		keys = append(keys, key)
	}
	profileGroupSIDLookups.Unlock()
	t.Cleanup(func() {
		profileGroupSIDLookups.Lock()
		for _, key := range keys {
			delete(profileGroupSIDLookups.calls, key)
		}
		profileGroupSIDLookups.Unlock()
		close(stalled)
		profileGroupLocalDomain = previousDomain
	})
	lookup := func(name string) (string, error) { return "S-1-5-21-9-9-9-1001", nil }
	for _, name := range []string{`WS01\strict-users`, `.\strict-users`, `BUILTIN\Users`} {
		sids := newProfileGroupSIDs([]config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{name}}}}, lookup, time.Second)
		if sid, ok := sids.sid(name); !ok || sid != "S-1-5-21-9-9-9-1001" {
			t.Fatalf("local group %s while directory lookups stall: sid %q, %v", name, sid, ok)
		}
	}
	sids := newProfileGroupSIDs([]config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{`CORP\other`}}}}, lookup, 50*time.Millisecond)
	if _, ok := sids.sid(`CORP\other`); ok {
		t.Fatal("a directory lookup started past its bound")
	}
}
