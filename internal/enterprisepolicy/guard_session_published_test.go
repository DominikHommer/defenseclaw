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
// agent process (or, unnamed, the session) not blocked lets a call go on.
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
	// A process that cannot be named is proven by its session record alone;
	// a named one needs its own record.
	unnamed := SessionKey{Connector: "copilot", Session: "u-1"}
	if err := PublishForeignHookSessionDecision(root, identity, unnamed, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(unnamed, trustAll); err != nil || got.Deny {
		t.Fatalf("an unnamed process with a clean session record must be proven: %+v %v", got, err)
	}
	if _, err := check(SessionKey{Connector: "copilot", Session: "u-1", Process: "linux:b:3:100"}, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a named process without its own record must not be proven by the session: %v", err)
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
