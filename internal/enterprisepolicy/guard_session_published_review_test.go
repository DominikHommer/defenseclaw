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
	"crypto/sha256"
	"errors"
	"fmt"
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

// Review P1 (GAP-0352, loop round 3): the pending mark is metadata of the
// account's private session store in the gateway's data directory, not of
// anything in the record tree a standard user can list. An account that
// could change the record tree (move its folder away, or have the tree
// invalidated) cannot clear it. Clearing it revokes the account's records,
// even ones the account brought back, and removes the emptied folder, so
// the next allow starts clean; a clear that cannot revoke a record keeps
// the mark. A store the mark created goes with it; the gateway's own store
// keeps what it holds. A store that is not a folder denies.
func TestForeignHookRemovalPendingMarkIsOutOfTheRecordTree(t *testing.T) {
	withoutPublishedSessionACL(t)
	dataDir, root := t.TempDir(), t.TempDir()
	identity := publishedSessionTestIdentity(t)
	other := publishedSessionOtherIdentity(identity)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	record, _ := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	dir, _ := PublishedSessionIdentityDir(root, identity)
	store := ForeignHookSessionStoreDir(dataDir, identity)
	if filepath.Dir(store) != filepath.Join(dataDir, sessionDirName) {
		t.Fatalf("the mark must live on the gateway's session store: %s", store)
	}
	pending := func(id string) bool {
		t.Helper()
		got, err := ForeignHookRemovalPending(dataDir, id)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	check := func() error {
		t.Helper()
		_, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
		return err
	}
	allow := func() {
		t.Helper()
		if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	allow()
	if pending(identity) {
		t.Fatal("a clean account must not be held")
	}
	if err := MarkForeignHookRemovalPending(dataDir, identity); err != nil {
		t.Fatal(err)
	}
	if !pending(identity) || pending(other) {
		t.Fatal("only this account must be held")
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Lstat(store); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("a missing store must be created 0700: %v %v", info, err)
		}
	}
	// Whatever an account does to the record tree, the mark stays.
	aside := filepath.Join(t.TempDir(), "aside")
	if err := os.Rename(dir, aside); err != nil {
		t.Fatal(err)
	}
	if err := InvalidatePublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	if !pending(identity) {
		t.Fatal("moving the record folder away, or invalidating the tree, must not clear the mark")
	}
	if err := os.Rename(aside, dir); err != nil {
		t.Fatal(err)
	}

	// A clear that cannot revoke the record the account brought back keeps
	// the mark.
	release := heldOpenPublishedSessionRecord(t, record)
	previousExpire, previousCreate := publishedSessionExpire, publishedSessionCreate
	publishedSessionExpire = func(string) error { return errors.New("the volume is read-only") }
	publishedSessionCreate = func(name string) (*os.File, error) {
		return nil, &os.PathError{Op: "open", Path: name, Err: errors.New("no space left on device")}
	}
	t.Cleanup(func() { publishedSessionExpire, publishedSessionCreate = previousExpire, previousCreate })
	if err := ClearForeignHookRemovalPending(dataDir, root, identity); err == nil || !pending(identity) {
		t.Fatalf("a clear that cannot revoke a record must keep the mark: %v", err)
	}
	publishedSessionExpire, publishedSessionCreate = previousExpire, previousCreate
	release()
	if err := ClearForeignHookRemovalPending(dataDir, root, identity); err != nil {
		t.Fatal(err)
	}
	if pending(identity) || publishedSessionTestExists(dir) || publishedSessionTestExists(store) {
		t.Fatal("the clear must end the mark and remove the emptied record folder and the store the mark created")
	}
	if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("the record from before the clear must be revoked: %v", err)
	}
	allow()
	if err := check(); err != nil {
		t.Fatalf("after the clear, a new allow proves the process: %v", err)
	}

	// The gateway's own store keeps what it holds; only the mark goes.
	kept := filepath.Join(store, "p-x.json")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kept, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MarkForeignHookRemovalPending(dataDir, identity); err != nil || !pending(identity) {
		t.Fatalf("mark the gateway's store: %v", err)
	}
	if err := ClearForeignHookRemovalPending(dataDir, root, identity); err != nil || pending(identity) || !publishedSessionTestExists(kept) {
		t.Fatalf("the clear must keep the gateway's records: %v", err)
	}
	if err := os.WriteFile(ForeignHookSessionStoreDir(dataDir, other), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ForeignHookRemovalPending(dataDir, other); err == nil {
		t.Fatal("a store that is not a folder must be an error, which denies")
	}
}

// Review P1 (GAP-0352, loop round 2): the lifecycle asks whether the hook
// would refuse anything in the record tree before it restores the tree's
// access, and then invalidates every account's records. A refused root,
// account folder or record, or an entry that is no account folder, is
// something another account could have changed. The invalidation deletes
// the records and the emptied account folders, removes the stray entry,
// and revokes in place a record a reader holds open.
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
	otherDir, _ := PublishedSessionIdentityDir(root, publishedSessionOtherIdentity(identity))
	if err := os.MkdirAll(otherDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherDir, "copilot-p-x.json"), []byte("{}"), 0o644); err != nil {
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
	// Review P1 (loop round 3): the root is checked whatever it holds. An
	// account that could change it may have moved its folder out, to bring
	// it back after the check; and a file in it is no account folder.
	empty := t.TempDir()
	refused = empty
	if err := PublishedSessionTreeProblem(empty, PublishedSessionTrust{}); err == nil || !strings.Contains(err.Error(), empty) {
		t.Fatalf("an empty root the hook refuses must be a problem: %v", err)
	}
	refused = ""
	if err := PublishedSessionTreeProblem(empty, PublishedSessionTrust{}); err != nil {
		t.Fatalf("an empty root the hook trusts is no problem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(empty, "x.hold"), []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := PublishedSessionTreeProblem(empty, PublishedSessionTrust{}); err == nil || !strings.Contains(err.Error(), "not an account folder") {
		t.Fatalf("a file in the root must be a problem: %v", err)
	}

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
	if !publishedSessionTestExists(heldRecord) {
		t.Fatal("the held record stays, revoked in place")
	}
	if publishedSessionTestExists(otherDir) {
		t.Fatal("an emptied account folder must go")
	}
	release()
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll); err != nil {
		t.Fatalf("the next allow after the invalidation proves the process: %v", err)
	}
}

// Review P1 (GAP-0352, loop round 3): while the record root let another
// account change it, the account moved its folder away, so the root was
// empty when the lifecycle checked it, and brought the folder back before
// the access was put back. The empty root is still the tree's problem, so
// the lifecycle closes the root and invalidates what it then holds: the old
// allow proves nothing.
func TestPublishedSessionTreeProblemSeesAFolderMovedOutOfAnEmptyRoot(t *testing.T) {
	withoutPublishedSessionACL(t)
	root := t.TempDir()
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	dir, _ := PublishedSessionIdentityDir(root, identity)
	aside := filepath.Join(t.TempDir(), "aside")
	if err := os.Rename(dir, aside); err != nil {
		t.Fatal(err)
	}
	// The guardian's revocation finds nothing to revoke.
	if err := RemovePublishedForeignHookSessions(root, identity, []string{"copilot"}); err != nil {
		t.Fatal(err)
	}
	previousFolder := publishedSessionFolderTrust
	publishedSessionFolderTrust = func(path string, _ PublishedSessionTrust, _ int) error {
		if path == root {
			return errors.New(root + " is writable by another account")
		}
		return nil
	}
	t.Cleanup(func() { publishedSessionFolderTrust = previousFolder })
	problem := PublishedSessionTreeProblem(root, PublishedSessionTrust{})
	// The account brings the folder back after the check.
	if err := os.Rename(aside, dir); err != nil {
		t.Fatal(err)
	}
	if problem == nil {
		t.Fatal("an empty root another account could change must be the tree's problem")
	}
	if err := InvalidatePublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	if got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("the allow the account brought back must prove nothing: %+v %v", got, err)
	}
}

// Review P1 (GAP-0352, loop round 3): the guardian trusts its revocation of
// an account's records only in a tree the hook trusts: the root and the
// folders above it, even with no account folder in the root, and the
// account's folder and its files. Another account's folder is not this
// account's problem, and a missing root is none.
func TestPublishedSessionAccountProblemSeesWhatTheHookWouldRefuse(t *testing.T) {
	withoutPublishedSessionACL(t)
	root := t.TempDir()
	identity := publishedSessionTestIdentity(t)
	other := publishedSessionOtherIdentity(identity)
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
	if err := PublishedSessionAccountProblem(filepath.Join(root, "missing"), identity, PublishedSessionTrust{}); err != nil {
		t.Fatalf("a missing root is no problem: %v", err)
	}
	refused = root
	if err := PublishedSessionAccountProblem(root, identity, PublishedSessionTrust{}); err == nil {
		t.Fatal("an empty root the hook refuses must be a problem")
	}
	refused = ""
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	for _, id := range []string{identity, other} {
		if err := PublishForeignHookSessionDecision(root, id, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := PublishedSessionAccountProblem(root, identity, PublishedSessionTrust{}); err != nil {
		t.Fatalf("a tree the hook trusts: %v", err)
	}
	dir, _ := PublishedSessionIdentityDir(root, identity)
	record, _ := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	for _, path := range []string{dir, record} {
		refused = path
		if err := PublishedSessionAccountProblem(root, identity, PublishedSessionTrust{}); err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("%s refused must be the account's problem: %v", path, err)
		}
	}
	refused, _ = PublishedSessionIdentityDir(root, other)
	if err := PublishedSessionAccountProblem(root, identity, PublishedSessionTrust{}); err != nil {
		t.Fatalf("another account's folder is not this account's problem: %v", err)
	}
}

// Review P1 (GAP-0352, loop round 3): the pending mark sits on the
// gateway's private session store, the folder the gateway has used since
// 1.0.3 (<data dir>/foreign-hook-sessions/<first 20 bytes of the SHA-256 of
// the identity>), so an upgraded gateway keeps its session records and the
// guardian marks the folder the gateway reads.
func TestForeignHookSessionStoreDirIsTheGatewaysStore(t *testing.T) {
	dataDir := t.TempDir()
	for _, identity := range []string{"1001", "S-1-5-21-1111-2222-3333-1001"} {
		digest := sha256.Sum256([]byte(identity))
		want := filepath.Join(dataDir, "foreign-hook-sessions", fmt.Sprintf("%x", digest[:20]))
		if got := ForeignHookSessionStoreDir(dataDir, identity); got != want {
			t.Fatalf("%s: store %s, want %s", identity, got, want)
		}
	}
	if got, want := ForeignHookSessionStoreDir(dataDir, "s-1-5-21-1111-2222-3333-1001"), ForeignHookSessionStoreDir(dataDir, "S-1-5-21-1111-2222-3333-1001"); got != want {
		t.Fatalf("a SID names one store whatever its case: %s %s", got, want)
	}
	if _, err := ForeignHookRemovalPending("relative", "1001"); err != nil {
		t.Fatalf("no data directory holds no mark: %v", err)
	}
	if err := MarkForeignHookRemovalPending("", "1001"); err == nil {
		t.Fatal("a mark without a data directory must be an error")
	}
}
