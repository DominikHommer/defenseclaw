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

func trustAll(string) error { return nil }

// GAP-0352: the gateway's answer for every session exchange is written to
// the protected record, and during an outage only a record that proves the
// agent process not blocked lets a call go on.
func TestPublishedForeignHookSessionRecordRoundTrip(t *testing.T) {
	withoutPublishedSessionACL(t)
	root := t.TempDir()
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "linux:b:1:100"}
	clean := GuardDecision{}
	check := func(k SessionKey, trust func(string) error) (GuardDecision, error) {
		t.Helper()
		return CheckPublishedForeignHookSession(root, identity, k, clean, trust)
	}

	if _, err := check(key, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("no record must prove nothing: %v", err)
	}
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(key, trustAll); err != nil || got.Deny {
		t.Fatalf("an allowed process must be proven unblocked: %+v %v", got, err)
	}
	reason := foreignHookBlockedPrefix + " When this agent session started, the project hook file /repo/.github/hooks/x.json defined a hook."
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{Deny: true, Reason: reason}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(key, trustAll); err != nil || !got.Deny || got.Reason != reason {
		t.Fatalf("a blocked process must deny with the gateway's reason: %+v %v", got, err)
	}
	// Another session of the blocked process, and the blocked session in an
	// unnamed process, are denied too.
	if got, err := check(SessionKey{Connector: "copilot", Session: "s-2", Process: key.Process}, trustAll); err != nil || !got.Deny {
		t.Fatalf("a new session of a blocked process must deny: %+v %v", got, err)
	}
	if got, err := check(SessionKey{Connector: "copilot", Session: "s-1"}, trustAll); err != nil || !got.Deny {
		t.Fatalf("a blocked session must deny: %+v %v", got, err)
	}
	// The allow that clears the block.
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(key, trustAll); err != nil || got.Deny {
		t.Fatalf("the clearing allow must prove the process unblocked: %+v %v", got, err)
	}
	// Another connector, another process or another account proves nothing.
	for _, other := range []SessionKey{
		{Connector: "opencode", Session: "s-1", Process: key.Process},
		{Connector: "copilot", Session: "s-1", Process: "linux:b:2:100"},
	} {
		if _, err := check(other, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("%+v: a record of another key must not prove this one: %v", other, err)
		}
	}
	if _, err := CheckPublishedForeignHookSession(root, publishedSessionOtherIdentity(identity), key, clean, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("another account's record must not prove this one: %v", err)
	}
	// A record that fails the trust check, is corrupt, has unknown fields or
	// names another key blocks.
	if _, err := check(key, func(string) error { return errors.New("writable by the user") }); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("an untrusted record must prove nothing: %v", err)
	}
	path, ok := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	if !ok {
		t.Fatal("no record path")
	}
	for name, content := range map[string]string{
		"corrupt":        `{"v":1,"connector":"copilot"`,
		"unknown field":  `{"v":1,"connector":"copilot","kind":"p","id":"` + key.Process + `","blocked":false,"at":"2026-10-21T00:00:00Z","x":1}`,
		"other key":      `{"v":1,"connector":"copilot","kind":"p","id":"linux:b:9:9","blocked":false,"at":"2026-10-21T00:00:00Z"}`,
		"other version":  `{"v":2,"connector":"copilot","kind":"p","id":"` + key.Process + `","blocked":false,"at":"2026-10-21T00:00:00Z"}`,
		"no time":        `{"v":1,"connector":"copilot","kind":"p","id":"` + key.Process + `","blocked":false,"at":""}`,
		"trailing value": `{"v":1,"connector":"copilot","kind":"p","id":"` + key.Process + `","blocked":false,"at":"2026-10-21T00:00:00Z"} {}`,
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := check(key, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("%s: the record must prove nothing: %v", name, err)
		}
	}
	// The guardian removed a Copilot hook of this account: every Copilot
	// record goes, the other connectors' stay.
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	opencode := SessionKey{Connector: "opencode", Session: "o-1", Process: key.Process}
	if err := PublishForeignHookSessionDecision(root, identity, opencode, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := RemovePublishedForeignHookSessions(root, identity, []string{"copilot"}); err != nil {
		t.Fatal(err)
	}
	if _, err := check(key, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a removal must clear the connector's records: %v", err)
	}
	if got, err := check(opencode, trustAll); err != nil || got.Deny {
		t.Fatalf("another connector's record must stay: %+v %v", got, err)
	}
	// Review P2: a session record alone proves nothing. An agent process the
	// hook cannot name may be one that started during the outage and
	// resumed the session ID, and a named one needs its own record.
	unnamed := SessionKey{Connector: "copilot", Session: "u-1"}
	if err := PublishForeignHookSessionDecision(root, identity, unnamed, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(unnamed, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) || got.Deny {
		t.Fatalf("an unnamed process must not be proven by a clean session record: %+v %v", got, err)
	}
	if _, err := check(SessionKey{Connector: "copilot", Session: "u-1", Process: "linux:b:3:100"}, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a named process without its own record must not be proven by the session: %v", err)
	}
}

// Review P2 (GAP-0352): an answer older than publishedSessionMaxAge, by the
// record's time or its modification time, proves nothing, and neither does
// a record that was deleted, replaced or expired after the hook read it.
func TestPublishedForeignHookSessionRefusesAStaleOrChangedAnswer(t *testing.T) {
	withoutPublishedSessionACL(t)
	root := t.TempDir()
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	path, ok := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	if !ok {
		t.Fatal("no record path")
	}
	sessionPath, _ := PublishedSessionRecordPath(root, identity, "copilot", sessionKindSession, key.Session)
	check := func(trust func(string) error) (GuardDecision, error) {
		t.Helper()
		return CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trust)
	}
	allow := func(at time.Time) {
		t.Helper()
		if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, at); err != nil {
			t.Fatal(err)
		}
	}
	allow(time.Now())
	if got, err := check(trustAll); err != nil || got.Deny {
		t.Fatalf("a fresh allow must prove the process unblocked: %+v %v", got, err)
	}
	old := time.Now().Add(-publishedSessionMaxAge - time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := check(trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a record older than the limit must prove nothing: %v", err)
	}
	allow(old)
	if _, err := check(trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("an answer older than the limit must prove nothing: %v", err)
	}
	// Between the read of the process record and the end of the check (the
	// session record's trust check runs in between).
	for name, change := range map[string]func(){
		"deleted": func() { _ = os.Remove(path) },
		"expired": func() { _ = publishedSessionExpire(path) },
		"replaced": func() {
			data, _ := os.ReadFile(path)
			_ = os.WriteFile(path+".new", data, 0o644)
			_ = os.Rename(path+".new", path)
		},
	} {
		allow(time.Now())
		changed := false
		_, err := check(func(p string) error {
			if p == sessionPath && !changed {
				changed = true
				change()
			}
			return nil
		})
		if !changed || !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("%s after the read: the record must prove nothing (changed=%v): %v", name, changed, err)
		}
	}
}

// Review P1 (GAP-0352): a revocation of a record that can be neither
// deleted nor replaced (a Windows reader holds it open) must not depend on
// creating the deny marker: on a full volume that fails too. The record is
// expired in place, which needs no space, and the hook refuses it. Only when
// every override fails is the revocation an error.
func TestPublishedForeignHookSessionRevocationSurvivesAMarkerThatCannotBeCreated(t *testing.T) {
	withoutPublishedSessionACL(t)
	root := t.TempDir()
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	path, ok := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	if !ok {
		t.Fatal("no record path")
	}
	check := func() (GuardDecision, error) {
		t.Helper()
		return CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
	}
	allow := func() {
		t.Helper()
		if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if got, err := check(); err != nil || got.Deny {
			t.Fatalf("the allow must prove the process unblocked: %+v %v", got, err)
		}
	}
	full := errors.New("there is not enough space on the disk")
	previousCreate := publishedSessionCreate
	publishedSessionCreate = func(name string) (*os.File, error) { return nil, &os.PathError{Op: "open", Path: name, Err: full} }
	t.Cleanup(func() { publishedSessionCreate = previousCreate })
	revocations := map[string]func() error{
		"block": func() error {
			_ = PublishForeignHookSessionDecision(root, identity, key, GuardDecision{Deny: true, Reason: foreignHookBlockedPrefix + " x"}, time.Now())
			return nil
		},
		"guardian removal": func() error { return RemovePublishedForeignHookSessions(root, identity, []string{"copilot"}) },
		"withdrawal":       func() error { return WithdrawPublishedForeignHookSession(root, identity, key) },
	}
	for name, revoke := range revocations {
		allow()
		release := heldOpenPublishedSessionRecord(t, path)
		if err := revoke(); err != nil {
			t.Fatalf("%s: an expired record is a revocation, not an error: %v", name, err)
		}
		if _, err := os.Lstat(publishedSessionDenyPath(path)); !os.IsNotExist(err) {
			t.Fatalf("%s: no marker can exist on a full volume: %v", name, err)
		}
		// The block also wrote the session record (not held), which denies;
		// the others leave the expired process record, which proves nothing.
		if got, err := check(); err == nil && !got.Deny {
			t.Fatalf("%s: the held record must stop proving the allow: %+v", name, got)
		}
		// The prune keeps a held, expired record (it cannot delete it) and it
		// keeps refusing it.
		prunePublishedSessionRecords(filepath.Dir(path), time.Now())
		if got, err := check(); err == nil && !got.Deny {
			t.Fatalf("%s: the pruned held record must still prove nothing: %+v", name, got)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("%s: the prune cannot delete the held record: %v", name, err)
		}
		release()
	}
	// An allow that replaces the record proves the process again.
	allow()

	// Every override fails: the revocation reports it.
	release := heldOpenPublishedSessionRecord(t, path)
	defer release()
	previousExpire := publishedSessionExpire
	publishedSessionExpire = func(string) error { return errors.New("the volume is read-only") }
	t.Cleanup(func() { publishedSessionExpire = previousExpire })
	if err := RemovePublishedForeignHookSessions(root, identity, []string{"copilot"}); err == nil {
		t.Fatal("a revocation that changed nothing must report it")
	}
}

// Review P2 (GAP-0352): the removals the guardian could not write to its
// ledger are held next to the account's records; the gateway reads only
// that account's entries, and a hold that is not a regular file or does
// not parse is an error, which denies.
func TestForeignHookRemovalHoldRoundTrip(t *testing.T) {
	root := t.TempDir()
	identity := publishedSessionTestIdentity(t)
	if removals, info, err := ReadForeignHookRemovalHold(root, identity); err != nil || removals != nil || info != nil {
		t.Fatalf("no hold must hold nothing: %v %v %v", removals, info, err)
	}
	path, ok := ForeignHookRemovalHoldPath(root, identity)
	dir, _ := PublishedSessionIdentityDir(root, identity)
	if !ok || path != dir+".hold" {
		t.Fatalf("hold path %q, want next to %q", path, dir)
	}
	now := time.Now().UTC()
	data, err := EncodeForeignHookRemovals(nil, []ForeignHookRemoval{
		{Identity: identity, Connector: "copilot", Path: "/home/a/.copilot/hooks/x.json", At: now.Format(time.RFC3339), Mark: "linux:b:200"},
		{Identity: publishedSessionOtherIdentity(identity), Connector: "copilot", Path: "/home/b/x.json", At: now.Format(time.RFC3339), Mark: "linux:b:200"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	removals, info, err := ReadForeignHookRemovalHold(root, identity)
	if err != nil || info == nil || len(removals) != 1 || removals[0].Path != "/home/a/.copilot/hooks/x.json" {
		t.Fatalf("the hold must give this account's removal only: %+v %v %v", removals, info, err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"removals":[`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadForeignHookRemovalHold(root, identity); err == nil {
		t.Fatal("a hold that does not parse must be an error")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadForeignHookRemovalHold(root, identity); err == nil {
		t.Fatal("a hold that is not a regular file must be an error")
	}
}

// A missing record root (no lifecycle folder, Secure Client, per-user)
// writes nothing and is not an error; the hook then blocks.
func TestPublishedForeignHookSessionWithoutARootWritesNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatalf("a missing root is not an error: %v", err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("the gateway must not create the lifecycle's root: %v", err)
	}
	if err := PublishForeignHookSessionDecision("", identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := PublishForeignHookSessionDecision(t.TempDir(), identity, SessionKey{Connector: "../x", Session: "s"}, GuardDecision{}, time.Now()); err == nil {
		t.Fatal("a connector name that is not a plain name must be refused")
	}
}

// A blocked answer that cannot be written must not leave the earlier allow
// behind (Linux and macOS: a root another account can write is refused).
func TestPublishedForeignHookSessionBlockThatCannotBeWrittenRemovesTheAllow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not make a Windows folder writable by others")
	}
	withoutPublishedSessionACL(t)
	root := t.TempDir()
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{Deny: true, Reason: foreignHookBlockedPrefix + " x"}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("an untrusted root must be refused: %v", err)
	}
	if _, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("the earlier allow must be gone: %v", err)
	}
}

// The prune keeps the newest records within the limit.
func TestPublishedForeignHookSessionPruneKeepsTheNewest(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for i := 0; i < publishedSessionDirLimit+5; i++ {
		path := filepath.Join(dir, "copilot-p-"+strings.Repeat("0", 3)+string(rune('a'+i%26))+strings.Repeat("x", i%7)+time.Duration(i).String()+".json")
		if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		mod := now.Add(-time.Duration(publishedSessionDirLimit+5-i) * time.Second)
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	old := filepath.Join(dir, "copilot-s-old.json")
	if err := os.WriteFile(old, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := now.Add(-sessionRecordTTL - time.Hour)
	if err := os.Chtimes(old, stale, stale); err != nil {
		t.Fatal(err)
	}
	prunePublishedSessionRecords(dir, now)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != publishedSessionDirLimit {
		t.Fatalf("kept %d records, want %d", len(entries), publishedSessionDirLimit)
	}
	if _, err := os.Lstat(old); !os.IsNotExist(err) {
		t.Fatal("a record past its TTL must be pruned")
	}
}

// heldOpenPublishedSessionRecord makes the replacement and the deletion of
// the record at path fail the way Windows refuses them while the account
// holds the record open without delete sharing.
func heldOpenPublishedSessionRecord(t *testing.T, path string) (release func()) {
	t.Helper()
	held := true
	previousRename, previousRemove := publishedSessionRename, publishedSessionRemove
	sharing := errors.New("the process cannot access the file because it is being used by another process")
	publishedSessionRename = func(from, to string) error {
		if held && to == path {
			return &os.LinkError{Op: "rename", Old: from, New: to, Err: sharing}
		}
		return previousRename(from, to)
	}
	publishedSessionRemove = func(name string) error {
		if held && name == path {
			return &os.PathError{Op: "remove", Path: name, Err: sharing}
		}
		return previousRemove(name)
	}
	t.Cleanup(func() { publishedSessionRename, publishedSessionRemove = previousRename, previousRemove })
	return func() { held = false }
}

// Review P1 (GAP-0352): a record the account holds open so that it can be
// neither replaced nor deleted must still stop proving an allow after a
// block, a guardian removal or a withdrawn answer: each writes the
// record's deny marker, which the hook honours whatever the record says.
// Only a later allow that replaced the record clears the marker.
func TestPublishedForeignHookSessionRevocationSurvivesARecordThatCannotBeReplaced(t *testing.T) {
	withoutPublishedSessionACL(t)
	root := t.TempDir()
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	path, ok := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	if !ok {
		t.Fatal("no record path")
	}
	check := func() (GuardDecision, error) {
		t.Helper()
		return CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
	}
	allow := func() {
		t.Helper()
		if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if got, err := check(); err != nil || got.Deny {
			t.Fatalf("the allow must prove the process unblocked: %+v %v", got, err)
		}
	}
	allow()

	// The gateway's block cannot replace or delete the held record.
	release := heldOpenPublishedSessionRecord(t, path)
	reason := foreignHookBlockedPrefix + " the project hook /repo/.github/hooks/x.json"
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{Deny: true, Reason: reason}, time.Now()); err == nil {
		t.Fatal("a block that cannot replace the record must report it")
	}
	if data, err := os.ReadFile(path); err != nil || !strings.Contains(string(data), `"blocked":false`) {
		t.Fatalf("the held record must still hold the old allow: %q %v", data, err)
	}
	if got, err := check(); err != nil || !got.Deny || got.Reason != reason {
		t.Fatalf("the deny marker must deny with the gateway's reason: %+v %v", got, err)
	}
	// An allow that cannot replace the held record leaves the marker.
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err == nil {
		t.Fatal("an allow that cannot replace the record must report it")
	}
	if got, err := check(); err != nil || !got.Deny {
		t.Fatalf("an allow that did not replace the record must not clear the marker: %+v %v", got, err)
	}
	// The allow that replaced the record clears it.
	release()
	allow()
	if _, err := os.Lstat(publishedSessionDenyPath(path)); !os.IsNotExist(err) {
		t.Fatalf("the replacing allow must remove the marker: %v", err)
	}

	// The guardian's removal cannot delete the held record.
	release = heldOpenPublishedSessionRecord(t, path)
	if err := RemovePublishedForeignHookSessions(root, identity, []string{"copilot"}); err != nil {
		t.Fatalf("a marker written for a held record is a revocation, not an error: %v", err)
	}
	if got, err := check(); err != nil || !got.Deny || !strings.HasPrefix(got.Reason, foreignHookBlockedPrefix) {
		t.Fatalf("the guardian's marker must deny: %+v %v", got, err)
	}
	// A marker whose record still exists survives the prune; once the record
	// is gone, the marker goes with the next prune.
	prunePublishedSessionRecords(filepath.Dir(path), time.Now())
	if _, err := os.Lstat(publishedSessionDenyPath(path)); err != nil {
		t.Fatalf("the prune must keep the marker of a record that stays: %v", err)
	}
	release()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	prunePublishedSessionRecords(filepath.Dir(path), time.Now())
	if _, err := os.Lstat(publishedSessionDenyPath(path)); !os.IsNotExist(err) {
		t.Fatalf("the prune must remove the marker of a record that is gone: %v", err)
	}

	// The gateway's withdrawn answer cannot delete the held record.
	allow()
	release = heldOpenPublishedSessionRecord(t, path)
	if err := WithdrawPublishedForeignHookSession(root, identity, key); err != nil {
		t.Fatal(err)
	}
	if got, err := check(); err != nil || !got.Deny {
		t.Fatalf("a withdrawn answer must not prove the process unblocked: %+v %v", got, err)
	}
	release()
	// A withdrawal that can delete the records leaves them missing.
	allow()
	if err := WithdrawPublishedForeignHookSession(root, identity, key); err != nil {
		t.Fatal(err)
	}
	if _, err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a withdrawn answer must prove nothing: %v", err)
	}
	// Anything at a marker path denies, even what does not decode.
	allow()
	if err := os.WriteFile(publishedSessionDenyPath(path), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := check(); err != nil || !got.Deny {
		t.Fatalf("a marker that does not decode must still deny: %+v %v", got, err)
	}
}
