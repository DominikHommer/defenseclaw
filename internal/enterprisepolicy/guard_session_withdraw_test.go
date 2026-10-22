// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"testing"
	"time"
)

// publishedSessionWithdrawTestBlock is a session-start scan that found an
// unapproved hook: the session and its agent process are blocked.
func publishedSessionWithdrawTestBlock() GuardDecision {
	return GuardDecision{
		Deny:     true,
		Reason:   foreignHookBlockedPrefix + " the project file /repo/.github/hooks/x.json defines a hook.",
		Findings: []Finding{{Connector: "copilot", Scope: ScopeProject, Path: "/repo/.github/hooks/x.json", Event: "preToolUse", Digest: "abcd"}},
	}
}

// Review P1 (GAP-0352, 1.0.4 guard loop round 2): the gateway records a
// block in its private store before it publishes it. A gateway that stopped
// between the two left the earlier allow in the protected record: with the
// hook file removed, the outage scan was clean and the hook honored the
// allow, while the gateway, once back, denies from its store. The gateway
// now takes the protected records of the key out of use right before the
// first write of a block (SessionUpdate.BeforeBlock,
// WithdrawPublishedForeignHookSession), for each way a block is recorded:
//   - a session start that finds an unapproved hook;
//   - a block carried from a blocked session to the agent process that
//     calls in it (its own allow was published earlier);
//
// and an exchange that records no block withdraws nothing.
func TestApplyForeignHookSessionWithdrawsTheProtectedAllowBeforeItRecordsABlock(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	stateDir := t.TempDir()
	withdrawals := 0
	// blockedInStore is which of the key's private records are blocked.
	blockedInStore := func(key SessionKey) [2]bool {
		t.Helper()
		var blocked [2]bool
		for i, entry := range []struct{ kind, id string }{{sessionKindProcess, key.Process}, {sessionKindSession, key.Session}} {
			record, exists, err := readSessionRecord(sessionPathInDir(stateDir, key.Connector, entry.kind, entry.id))
			if err != nil {
				t.Fatal(err)
			}
			blocked[i] = exists && record.Blocked
		}
		return blocked
	}
	apply := func(key SessionKey, start bool, decision GuardDecision, publish bool) GuardDecision {
		t.Helper()
		before := blockedInStore(key)
		got := ApplyForeignHookSession(SessionUpdate{
			StateDir: stateDir, Key: key, SessionStart: start, Decision: decision, Now: time.Now(),
			BeforeBlock: func() {
				withdrawals++
				if blockedInStore(key) != before {
					t.Error("the block must not be in the store before the protected records are withdrawn")
				}
				if err := WithdrawPublishedForeignHookSession(root, identity, key); err != nil {
					t.Errorf("withdraw: %v", err)
				}
			},
		})
		if publish {
			if err := publishCurrent(root, identity, key, got, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		return got
	}
	proves := func(key SessionKey) bool {
		t.Helper()
		got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
		return err == nil && !got.Deny
	}

	// A session start that finds an unapproved hook, in a process whose
	// earlier session was allowed.
	first := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if got := apply(first, true, GuardDecision{}, true); got.Deny || withdrawals != 0 || !proves(first) {
		t.Fatalf("a clean session start is allowed, withdraws nothing and is proven: %+v %d", got, withdrawals)
	}
	again := SessionKey{Connector: "copilot", Session: "s-2", Process: "p-1"}
	// The gateway stops after the block is in its store, before it is
	// published.
	if got := apply(again, true, publishedSessionWithdrawTestBlock(), false); !got.Deny || withdrawals != 1 {
		t.Fatalf("the session start that found the hook is blocked once withdrawn: %+v %d", got, withdrawals)
	}
	for _, key := range []SessionKey{first, again} {
		if proves(key) {
			t.Fatalf("%+v: an allow the unpublished block overrules must prove nothing during the outage", key)
		}
	}
	if got := apply(again, false, GuardDecision{}, false); !got.Deny {
		t.Fatalf("the gateway, back, denies from its store: %+v", got)
	}

	// A session blocked in one agent process, resumed by another process
	// that was allowed in a session of its own: the block is carried to
	// that process.
	blocked := SessionKey{Connector: "copilot", Session: "s-3", Process: "p-0"}
	apply(blocked, true, publishedSessionWithdrawTestBlock(), true)
	other := SessionKey{Connector: "copilot", Session: "s-4", Process: "p-2"}
	withdrawals = 0
	if got := apply(other, true, GuardDecision{}, true); got.Deny || withdrawals != 0 || !proves(other) {
		t.Fatalf("the other process is allowed in its own session: %+v %d", got, withdrawals)
	}
	resumed := SessionKey{Connector: "copilot", Session: "s-3", Process: "p-2"}
	if got := apply(resumed, false, GuardDecision{}, false); !got.Deny || withdrawals != 1 {
		t.Fatalf("a call in the blocked session carries the block to the process, once withdrawn: %+v %d", got, withdrawals)
	}
	if proves(other) {
		t.Fatal("the process's earlier allow must prove nothing once the carried block is recorded, published or not")
	}

	// Withdrawing what was never published, or under no root, is no error.
	if err := WithdrawPublishedForeignHookSession(root, publishedSessionOtherIdentity(identity), first); err != nil {
		t.Fatal(err)
	}
	if err := WithdrawPublishedForeignHookSession("", identity, first); err != nil {
		t.Fatal(err)
	}
}

// Review P2 (GAP-0352, 1.0.4 guard loop round 2): the guardian withdraws the
// record generation before it publishes a removal. While it is withdrawn no
// allow proves anything, an answer the gateway stamps meanwhile carries no
// generation and proves nothing either, and the state stays closed until a
// bump past the withdrawn generation; a hook check that read the generation
// before the withdrawal fails its last read. A generation file that cannot
// be removed is bumped instead; one that can be neither removed nor bumped
// is an error.
func TestWithdrawPublishedSessionGenerationClosesUntilTheNextBump(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	proves := func() bool {
		t.Helper()
		got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
		return err == nil && !got.Deny
	}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil || !proves() {
		t.Fatalf("a fresh allow proves the process: %v", err)
	}
	before := publishedSessionTestGeneration(t, root)
	floor, err := WithdrawPublishedSessionGeneration(root)
	if err != nil || floor.UnixNano() != before {
		t.Fatalf("withdraw: floor %v, want %d: %v", floor, before, err)
	}
	if proves() {
		t.Fatal("a withdrawn generation proves nothing")
	}
	if generation, err := PublishedSessionGeneration(root); err == nil || generation != "" {
		t.Fatalf("the gateway reads no generation while it is withdrawn: %q %v", generation, err)
	}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil || proves() {
		t.Fatalf("an answer stamped while the generation is withdrawn proves nothing: %v", err)
	}
	// A pass that stopped here: a second withdrawal is no error, and the
	// state stays closed.
	if _, err := WithdrawPublishedSessionGeneration(root); err != nil || proves() {
		t.Fatalf("a withdrawn generation stays withdrawn: %v", err)
	}
	if err := BumpPublishedSessionGenerationPast(root, floor); err != nil {
		t.Fatal(err)
	}
	if after := publishedSessionTestGeneration(t, root); after <= before {
		t.Fatalf("the next generation is later than the withdrawn one: %d after %d", after, before)
	}
	if proves() {
		t.Fatal("the answers from before the bump prove nothing")
	}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil || !proves() {
		t.Fatalf("the next answer proves the process again: %v", err)
	}

	// A hook check that found no hold just before the guardian's hold, and
	// reads the generation after the guardian closed the records.
	previousList := publishedSessionHoldList
	t.Cleanup(func() { publishedSessionHoldList = previousList })
	publishedSessionHoldList = func(dir string) ([]string, error) {
		names, err := previousList(dir)
		if err := HoldPublishedSessionRemoval(root, identity); err != nil {
			t.Error(err)
		}
		if _, err := WithdrawPublishedSessionGeneration(root); err != nil {
			t.Error(err)
		}
		return names, err
	}
	if proves() {
		t.Fatal("a hook check whose last generation read follows the guardian's withdrawal must not allow")
	}
	publishedSessionHoldList = previousList
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	if err := ReleasePublishedSessionRemoval(root, identity); err != nil {
		t.Fatal(err)
	}

	// A generation file that cannot be removed is bumped instead.
	previousRemove, previousSet := publishedSessionRemove, publishedSessionSetTime
	t.Cleanup(func() { publishedSessionRemove, publishedSessionSetTime = previousRemove, previousSet })
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil || !proves() {
		t.Fatalf("a fresh allow proves the process: %v", err)
	}
	before = publishedSessionTestGeneration(t, root)
	publishedSessionRemove = func(string) error { return errors.New("the file is in use by another process") }
	if _, err := WithdrawPublishedSessionGeneration(root); err == nil {
		t.Fatal("a generation that was only bumped is reported")
	}
	if after := publishedSessionTestGeneration(t, root); after <= before || proves() {
		t.Fatalf("a generation that cannot be removed is bumped, which ends the allow: %d after %d", after, before)
	}
	publishedSessionSetTime = func(string, time.Time) error { return errors.New("the volume is read-only") }
	if _, err := WithdrawPublishedSessionGeneration(root); err == nil {
		t.Fatal("a generation that can be neither removed nor bumped is an error")
	}
	publishedSessionRemove, publishedSessionSetTime = previousRemove, previousSet

	// No generation file: nothing to withdraw.
	path, _ := PublishedSessionGenerationPath(root)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if floor, err := WithdrawPublishedSessionGeneration(root); err != nil || !floor.IsZero() {
		t.Fatalf("a missing generation is already withdrawn: %v %v", floor, err)
	}
	if _, err := WithdrawPublishedSessionGeneration("relative"); err == nil {
		t.Fatal("a relative root is refused")
	}
}
