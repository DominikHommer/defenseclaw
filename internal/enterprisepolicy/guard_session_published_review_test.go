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
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func publishedSessionTestExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// Review P2 (GAP-0352, loop round 2): an answer dated after now proves
// nothing. The clock was ahead when the gateway wrote the allow and was set
// back since: without the bound both ages are negative, and the allow would
// outlive the seven-day limit by as long as the clock was ahead. A small
// step back of the clock (publishedSessionClockSkew) still passes, and the
// prune drops a future-dated record like an expired one.
func TestPublishedForeignHookSessionRefusesAFutureDatedAnswer(t *testing.T) {
	withoutPublishedSessionACL(t)
	root := t.TempDir()
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	path, ok := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	if !ok {
		t.Fatal("no record path")
	}
	publish := func(at, modified time.Time) {
		t.Helper()
		if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, at); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	check := func() error {
		t.Helper()
		_, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
		return err
	}
	now := time.Now()
	// The record exists first: a publication that creates one prunes the
	// folder by the publication's time.
	publish(now, now)
	for _, tc := range []struct {
		name         string
		at, modified time.Time
	}{
		{"both a month ahead", now.Add(30 * 24 * time.Hour), now.Add(30 * 24 * time.Hour)},
		{"the record's time ahead", now.Add(time.Hour), now},
		{"the modification time ahead", now, now.Add(time.Hour)},
		{"just past the skew", now.Add(publishedSessionClockSkew + 10*time.Second), now},
	} {
		publish(tc.at, tc.modified)
		if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("%s: a future-dated answer must prove nothing: %v", tc.name, err)
		}
	}
	publish(now.Add(publishedSessionClockSkew/2), now.Add(publishedSessionClockSkew/2))
	if err := check(); err != nil {
		t.Fatalf("an answer within the clock skew must prove the process: %v", err)
	}
	ahead := now.Add(48 * time.Hour)
	if err := os.Chtimes(path, ahead, ahead); err != nil {
		t.Fatal(err)
	}
	prunePublishedSessionRecords(filepath.Dir(path), now)
	if publishedSessionTestExists(path) {
		t.Fatal("a future-dated record must be pruned")
	}
}

// Review P2 (GAP-0352, loop round 2): the removal step the gateway runs
// again after the guardian changed its removals during an exchange. The
// pending mark denies with its own reason, an unreadable ledger denies, a
// removal recorded after the agent process started denies, and a later
// process or another connector is not affected.
func TestApplyForeignHookRemovalsDeniesForTheMarkAndTheLedger(t *testing.T) {
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "linux:b:1:100"}
	now := time.Now()
	for name, err := range map[string]error{
		"the mark":                    ErrForeignHookRemovalPending,
		"the mark with another error": errors.Join(errors.New("the ledger is unreadable"), ErrForeignHookRemovalPending),
	} {
		if got := ApplyForeignHookRemovals(GuardDecision{}, key, nil, err, now); !got.Deny || !strings.Contains(got.Reason, "could not record the removal yet") {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	if got := ApplyForeignHookRemovals(GuardDecision{}, key, nil, errors.New("the ledger is unreadable"), now); !got.Deny || !strings.Contains(got.Reason, "cannot verify") {
		t.Fatalf("an unreadable ledger must deny: %+v", got)
	}
	removals := []ForeignHookRemoval{{Identity: "1001", Connector: "copilot", Path: "/home/a/.copilot/hooks/x.json", At: now.UTC().Format(time.RFC3339), Mark: "linux:b:200"}}
	if got := ApplyForeignHookRemovals(GuardDecision{}, key, removals, nil, now); !got.Deny || !strings.Contains(got.Reason, "started before DefenseClaw removed") {
		t.Fatalf("a process that started before the removal must be denied: %+v", got)
	}
	for _, other := range []SessionKey{
		{Connector: "copilot", Session: "s-1", Process: "linux:b:1:300"},
		{Connector: "opencode", Session: "s-1", Process: key.Process},
	} {
		if got := ApplyForeignHookRemovals(GuardDecision{}, other, removals, nil, now); got.Deny {
			t.Fatalf("%+v must not be denied: %+v", other, got)
		}
	}
}

// Review P2 (GAP-0352, loop round 2): a removal the guardian could record
// neither in its ledger nor in the hold leaves the account's pending mark,
// metadata of its record folder. While it is set the hook takes no record
// of the account as proof, and the gateway writes no allow in its folder; a
// block still revokes, and other accounts are not held. Clearing it revokes
// what the folder holds and removes the folder, so the next allow starts
// clean. A clear that cannot revoke a record keeps the mark.
func TestForeignHookRemovalPendingMarkHoldsTheAccountClosedUntilCleared(t *testing.T) {
	withoutPublishedSessionACL(t)
	root := t.TempDir()
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	later := SessionKey{Connector: "opencode", Session: "s-2", Process: "p-2"}
	record, _ := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	laterRecord, _ := PublishedSessionRecordPath(root, identity, "opencode", sessionKindProcess, later.Process)
	dir, _ := PublishedSessionIdentityDir(root, identity)
	check := func(k SessionKey) error {
		t.Helper()
		_, err := CheckPublishedForeignHookSession(root, identity, k, GuardDecision{}, trustAll)
		return err
	}
	pending := func(id string) bool {
		t.Helper()
		got, err := ForeignHookRemovalPending(root, id)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	allow := func(k SessionKey) {
		t.Helper()
		if err := PublishForeignHookSessionDecision(root, identity, k, GuardDecision{}, time.Now()); err != nil {
			t.Fatalf("an allow for %+v: %v", k, err)
		}
	}
	allow(key)
	if err := check(key); err != nil || pending(identity) {
		t.Fatalf("a clean account: %v, pending %v", err, pending(identity))
	}
	if err := MarkForeignHookRemovalPending(root, identity); err != nil {
		t.Fatal(err)
	}
	if !pending(identity) || pending(publishedSessionOtherIdentity(identity)) {
		t.Fatal("only this account must be held")
	}
	if err := check(key); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a fresh allow must prove nothing while the mark is set: %v", err)
	}
	allow(later)
	if publishedSessionTestExists(laterRecord) {
		t.Fatal("no allow may be written for a held account")
	}
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{Deny: true, Reason: foreignHookBlockedPrefix + " x"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if publishedSessionTestExists(record) {
		t.Fatal("a block must still revoke the allow of a held account")
	}

	// A record from before the mark, and a clear that cannot revoke it.
	if err := writePublishedSessionRecord(record, PublishedSessionRecord{Version: publishedSessionVersion, Connector: "copilot", Kind: sessionKindProcess, ID: key.Process, At: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	release := heldOpenPublishedSessionRecord(t, record)
	previousExpire, previousCreate := publishedSessionExpire, publishedSessionCreate
	publishedSessionExpire = func(string) error { return errors.New("the volume is read-only") }
	publishedSessionCreate = func(name string) (*os.File, error) {
		return nil, &os.PathError{Op: "open", Path: name, Err: errors.New("no space left on device")}
	}
	t.Cleanup(func() { publishedSessionExpire, publishedSessionCreate = previousExpire, previousCreate })
	if err := ClearForeignHookRemovalPending(root, identity); err == nil || !pending(identity) {
		t.Fatalf("a clear that cannot revoke a record must keep the mark: %v", err)
	}
	publishedSessionExpire, publishedSessionCreate = previousExpire, previousCreate
	release()

	if err := ClearForeignHookRemovalPending(root, identity); err != nil {
		t.Fatal(err)
	}
	if pending(identity) || publishedSessionTestExists(dir) {
		t.Fatal("the clear must end the mark and remove the emptied folder")
	}
	if err := check(key); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a record from before the mark must be revoked: %v", err)
	}
	allow(key)
	if err := check(key); err != nil {
		t.Fatalf("after the mark, a new allow proves the process: %v", err)
	}

	if runtime.GOOS == "windows" {
		// The folder the guardian creates is Administrators-owned, which
		// takes an elevated test.
		return
	}
	other := publishedSessionOtherIdentity(identity)
	otherDir, _ := PublishedSessionIdentityDir(root, other)
	if err := MarkForeignHookRemovalPending(root, other); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(otherDir); err != nil || info.Mode().Perm() != 0o700 || !pending(other) {
		t.Fatalf("a missing folder must be created closed, with the mark: %v %v", info, err)
	}
	if err := ClearForeignHookRemovalPending(root, other); err != nil || publishedSessionTestExists(otherDir) {
		t.Fatalf("the guardian's folder must go with its mark: %v", err)
	}
}

// Review P1 (GAP-0352, loop round 2): the lifecycle asks whether the hook
// would refuse anything in the record tree before it restores the tree's
// access, and then invalidates every account's records. A refused root,
// account folder or record, or an entry that is no account folder, is
// something another account could have changed. The invalidation keeps the
// guardian's hold and a pending mark (its folder emptied), deletes the
// records, and revokes in place a record a reader holds open.
func TestPublishedSessionRecordsAreInvalidatedWhereAnotherAccountCouldChangeThem(t *testing.T) {
	withoutPublishedSessionACL(t)
	root := t.TempDir()
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	held := SessionKey{Connector: "copilot", Session: "s-2", Process: "p-2"}
	for _, k := range []SessionKey{key, held} {
		if err := PublishForeignHookSessionDecision(root, identity, k, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	dir, _ := PublishedSessionIdentityDir(root, identity)
	record, _ := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	heldRecord, _ := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, held.Process)
	hold, _ := ForeignHookRemovalHoldPath(root, identity)
	if err := os.WriteFile(hold, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	marked, _ := PublishedSessionIdentityDir(root, publishedSessionOtherIdentity(identity))
	if err := os.MkdirAll(marked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(marked, "copilot-p-x.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := publishedSessionSetPending(marked, true); err != nil {
		t.Fatal(err)
	}

	refused := ""
	refuse := func(path string) error {
		if path == refused {
			return errors.New(path + " is writable by another account")
		}
		return nil
	}
	previousFile, previousFolder := publishedSessionFileTrust, publishedSessionFolderTrust
	publishedSessionFileTrust = func(path string, _ PublishedSessionTrust) error { return refuse(path) }
	publishedSessionFolderTrust = func(path string, _ PublishedSessionTrust, _ int) error { return refuse(path) }
	t.Cleanup(func() { publishedSessionFileTrust, publishedSessionFolderTrust = previousFile, previousFolder })
	if err := PublishedSessionTreeProblem(root, PublishedSessionTrust{}); err != nil {
		t.Fatalf("a tree the hook trusts: %v", err)
	}
	for _, path := range []string{root, dir, record} {
		refused = path
		if err := PublishedSessionTreeProblem(root, PublishedSessionTrust{}); err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("%s refused must be the tree's problem: %v", path, err)
		}
	}
	refused = ""
	stray := filepath.Join(root, "stray")
	if err := os.WriteFile(stray, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := PublishedSessionTreeProblem(root, PublishedSessionTrust{}); err == nil || !strings.Contains(err.Error(), "not an account folder") {
		t.Fatalf("an entry that is no account folder must be a problem: %v", err)
	}
	if err := PublishedSessionTreeProblem(filepath.Join(root, "missing"), PublishedSessionTrust{}); err != nil {
		t.Fatalf("a missing root is no problem: %v", err)
	}
	// A root with nothing but a hold has nothing to invalidate.
	onlyHold := t.TempDir()
	if err := os.WriteFile(filepath.Join(onlyHold, "x"+foreignHookRemovalHoldSuffix), []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	refused = onlyHold
	if err := PublishedSessionTreeProblem(onlyHold, PublishedSessionTrust{}); err != nil {
		t.Fatalf("a root with only a hold is no problem: %v", err)
	}
	refused = ""

	release := heldOpenPublishedSessionRecord(t, heldRecord)
	if err := InvalidatePublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]SessionKey{"deleted": key, "held open": held} {
		if got, err := CheckPublishedForeignHookSession(root, identity, k, GuardDecision{}, trustAll); err == nil && !got.Deny {
			t.Fatalf("%s: an invalidated record must not allow: %+v", name, got)
		}
	}
	if publishedSessionTestExists(record) || publishedSessionTestExists(stray) {
		t.Fatal("the records and the stray entry must go")
	}
	if !publishedSessionTestExists(heldRecord) || !publishedSessionTestExists(hold) {
		t.Fatal("the held record stays revoked in place, and the hold stays")
	}
	info, err := os.Lstat(marked)
	if err != nil || !publishedSessionPendingFlag(info) {
		t.Fatalf("the pending mark must stay: %v", err)
	}
	if entries, err := os.ReadDir(marked); err != nil || len(entries) != 0 {
		t.Fatalf("the marked folder must be emptied: %v %v", entries, err)
	}
	release()
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll); err != nil {
		t.Fatalf("the next allow after the invalidation proves the process: %v", err)
	}
}
