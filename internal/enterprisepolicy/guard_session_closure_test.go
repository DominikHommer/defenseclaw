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
	"strings"
	"testing"
	"time"
)

// Review P1 (GAP-0352, 1.0.4 guard loop round 3): removals that cannot be
// read (the account's pending mark, a ledger that fails its check, a record
// folder the gateway cannot locate) denied the call before the session
// state was looked at, so a session start that found an unapproved hook
// recorded no block and withdrew nothing: once the removals could be read
// again, the session and its agent process were allowed, and an earlier
// protected allow stayed usable during an outage. Now the block is still
// recorded (after BeforeBlock), and carried to the other key, while a call
// the removals alone deny writes nothing.
func TestApplyForeignHookSessionRecordsABlockWhileTheRemovalsCannotBeRead(t *testing.T) {
	for name, removalsErr := range map[string]error{
		"pending mark":            ErrForeignHookRemovalPending,
		"untrusted ledger":        errors.New("the removal ledger fails its trust check"),
		"record folder not found": errors.New("the protected foreign-hook session record folder cannot be located"),
	} {
		t.Run(name, func(t *testing.T) {
			stateDir := t.TempDir()
			withdrawals := 0
			apply := func(key SessionKey, start bool, decision GuardDecision, err error) GuardDecision {
				t.Helper()
				return ApplyForeignHookSession(SessionUpdate{
					StateDir: stateDir, Key: key, SessionStart: start, Decision: decision, RemovalsErr: err, Now: time.Now(),
					BeforeBlock: func() { withdrawals++ },
				})
			}
			key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
			if got := apply(key, false, GuardDecision{}, removalsErr); !got.Deny {
				t.Fatalf("removals that cannot be read deny the call: %+v", got)
			}
			if entries, err := os.ReadDir(stateDir); err != nil || len(entries) != 0 {
				t.Fatalf("a call the removals alone deny writes nothing: %v %v", entries, err)
			}
			if got := apply(key, true, publishedSessionWithdrawTestBlock(), removalsErr); !got.Deny || withdrawals != 1 {
				t.Fatalf("the session start that found the hook records its block after the withdrawal (%d): %+v", withdrawals, got)
			}
			// The removals can be read again and the hook file is gone.
			if got := apply(key, false, GuardDecision{}, nil); !got.Deny {
				t.Fatalf("the session the start blocked stays blocked: %+v", got)
			}
			// Another agent process resumes the blocked session while the
			// removals cannot be read: the block is carried to it.
			withdrawals = 0
			resumed := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-2"}
			if got := apply(resumed, false, GuardDecision{}, removalsErr); !got.Deny || withdrawals != 1 {
				t.Fatalf("the block is carried to the resuming process after the withdrawal (%d): %+v", withdrawals, got)
			}
			if got := apply(SessionKey{Connector: "copilot", Session: "s-9", Process: "p-2"}, false, GuardDecision{}, nil); !got.Deny {
				t.Fatalf("the carried block holds the process in its other sessions: %+v", got)
			}
		})
	}
}

// Review P1 (GAP-0352, 1.0.4 guard loop round 3): when the gateway cannot
// take out of use the records a block overrules, it removes the record
// folder's generation file. Every allow there, of every key, then proves
// nothing, an answer stamped meanwhile carries no generation and proves
// nothing either, and only a bump starts a generation again; an allow from
// before the close proves nothing after that bump. Closing what is closed
// is no error; a file that cannot be removed, or no record folder, is one.
func TestClosePublishedSessionGenerationEndsEveryAllowUntilTheNextBump(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	keys := []SessionKey{
		{Connector: "copilot", Session: "s-1", Process: "p-1"},
		{Connector: "copilot", Session: "s-2", Process: "p-2"},
	}
	proves := func(key SessionKey) bool {
		t.Helper()
		got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
		return err == nil && !got.Deny
	}
	for _, key := range keys {
		if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if !proves(key) {
			t.Fatalf("%+v: a fresh allow of the current generation proves the process", key)
		}
	}
	if err := ClosePublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if proves(key) {
			t.Fatalf("%+v: no allow proves anything once the generation is closed", key)
		}
	}
	if err := publishCurrent(root, identity, keys[0], GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if proves(keys[0]) {
		t.Fatal("an answer stamped while the generation is closed proves nothing")
	}
	if err := ClosePublishedSessionGeneration(root); err != nil {
		t.Fatalf("closing a closed generation is no error: %v", err)
	}
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	if proves(keys[1]) {
		t.Fatal("an allow from before the close proves nothing after the next bump")
	}
	if err := publishCurrent(root, identity, keys[1], GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !proves(keys[1]) {
		t.Fatal("the next allow proves the process again")
	}
	previous := publishedSessionRemove
	t.Cleanup(func() { publishedSessionRemove = previous })
	publishedSessionRemove = func(string) error { return errors.New("read-only file system") }
	if err := ClosePublishedSessionGeneration(root); err == nil {
		t.Fatal("a generation file that cannot be removed is an error")
	}
	publishedSessionRemove = previous
	if err := ClosePublishedSessionGeneration("relative"); err == nil {
		t.Fatal("no record folder is an error")
	}
}

// Review P1 (GAP-0352, 1.0.4 guard loop round 3): on a volume that is
// read-only the gateway can neither take a record out of use nor close the
// generation, so an allow there may be one that a block recorded since
// overrules. The hook refuses it, and blocks too when it cannot read the
// volume's state; a block still denies with its reason. A writable folder
// is not read-only.
func TestPublishedForeignHookSessionOnAReadOnlyVolumeProvesNothing(t *testing.T) {
	if readOnly, err := publishedSessionVolumeIsReadOnly(t.TempDir()); err != nil || readOnly {
		t.Fatalf("a writable test folder is not read-only: %v %v", readOnly, err)
	}
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	allowed := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	blocked := SessionKey{Connector: "copilot", Session: "s-2", Process: "p-2"}
	if err := publishCurrent(root, identity, allowed, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := publishCurrent(root, identity, blocked, publishedSessionWithdrawTestBlock(), time.Now()); err != nil {
		t.Fatal(err)
	}
	check := func(key SessionKey) (GuardDecision, error) {
		t.Helper()
		return CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
	}
	if got, err := check(allowed); err != nil || got.Deny {
		t.Fatalf("the allow proves the process: %+v %v", got, err)
	}
	previous := publishedSessionVolumeReadOnly
	t.Cleanup(func() { publishedSessionVolumeReadOnly = previous })
	publishedSessionVolumeReadOnly = func(path string) (bool, error) {
		if path != root {
			t.Errorf("checked %s, want the record folder %s", path, root)
		}
		return true, nil
	}
	if _, err := check(allowed); !errors.Is(err, ErrPublishedSessionUnavailable) || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("an allow on a read-only volume proves nothing: %v", err)
	}
	if got, err := check(blocked); err != nil || !got.Deny {
		t.Fatalf("a block still denies: %+v %v", got, err)
	}
	publishedSessionVolumeReadOnly = func(string) (bool, error) { return false, errors.New("statfs: input/output error") }
	if _, err := check(allowed); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a volume whose state cannot be read proves nothing: %v", err)
	}
	publishedSessionVolumeReadOnly = previous
	if _, err := check(allowed); err != nil {
		t.Fatalf("on a writable volume the allow proves the process: %v", err)
	}
}

// Review P1 (GAP-0352, 1.0.4 guard loop round 3): the guardian revokes an
// account's protected records when it can neither hold them nor withdraw
// their generation. Every allow of the account then proves nothing, also
// one whose record cannot be deleted (expired and overruled by its deny
// marker), with the generation unchanged, so the account's next allow
// proves again. An account with no records has nothing to revoke.
func TestRevokePublishedSessionAccountEndsTheAccountsAllows(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	keys := []SessionKey{
		{Connector: "copilot", Session: "s-1", Process: "p-1"},
		{Connector: "copilot", Session: "s-2", Process: "p-2"},
	}
	proves := func(key SessionKey) bool {
		t.Helper()
		got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
		return err == nil && !got.Deny
	}
	for _, key := range keys {
		if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if !proves(key) {
			t.Fatalf("%+v: a fresh allow proves the process", key)
		}
	}
	generation := publishedSessionTestGeneration(t, root)
	if err := RevokePublishedSessionAccount(root, identity); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if proves(key) {
			t.Fatalf("%+v: a revoked allow proves nothing", key)
		}
	}
	if publishedSessionTestGeneration(t, root) != generation {
		t.Fatal("the revocation does not change the generation")
	}
	if err := publishCurrent(root, identity, keys[0], GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !proves(keys[0]) {
		t.Fatal("the account's next allow proves the process again")
	}
	previous := publishedSessionRemove
	t.Cleanup(func() { publishedSessionRemove = previous })
	publishedSessionRemove = func(path string) error {
		if strings.HasSuffix(path, ".json") {
			return errors.New("the process cannot access the file because it is being used by another process")
		}
		return previous(path)
	}
	if err := RevokePublishedSessionAccount(root, identity); err != nil {
		t.Fatalf("a record that cannot be deleted is expired and marked: %v", err)
	}
	if proves(keys[0]) {
		t.Fatal("a record that could not be deleted proves nothing once it is revoked")
	}
	publishedSessionRemove = previous
	if err := RevokePublishedSessionAccount(root, publishedSessionOtherIdentity(identity)); err != nil {
		t.Fatalf("an account with no records has nothing to revoke: %v", err)
	}
	if err := RevokePublishedSessionAccount("relative", identity); err == nil {
		t.Fatal("no record folder is an error")
	}
}
