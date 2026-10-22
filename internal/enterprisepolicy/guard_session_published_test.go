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
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func trustAll(string) error { return nil }

// publishedSessionTestTrust names the gateway service the way a lifecycle
// does: a Windows key file lets it remove the key.
var publishedSessionTestTrust = PublishedSessionTrust{ServiceAccount: `NT SERVICE\` + managed.StandaloneWindowsGatewaySvc}

// withPublishedSessionKeysOfTheTestAccount accepts a key file the test
// account made, where production accepts only root's, SYSTEM's or
// Administrators'. A path in refused is not a key: it stands in for a file
// another account made with a key's name.
func withPublishedSessionKeysOfTheTestAccount(t *testing.T, refused ...string) {
	t.Helper()
	restore := OverridePublishedSessionKeyOwnerForTest(func(path string) (bool, error) {
		for _, name := range refused {
			if path == name {
				return false, nil
			}
		}
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return info.Mode().IsRegular(), nil
	})
	t.Cleanup(restore)
}

// publishedSessionTestRoot is a record folder with its key, as the
// lifecycle makes it.
func publishedSessionTestRoot(t *testing.T) string {
	t.Helper()
	withoutPublishedSessionACL(t)
	withPublishedSessionKeysOfTheTestAccount(t)
	root := filepath.Join(t.TempDir(), "sessions")
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := CreatePublishedSessionKey(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	return root
}

// publishCurrent publishes an answer the way the gateway does: with the key
// it reads first (none when it cannot read one).
func publishCurrent(root, identity string, key SessionKey, decision GuardDecision, now time.Time) error {
	recordKey, _ := ReadPublishedSessionKey(root)
	return PublishForeignHookSessionDecision(root, identity, key, decision, recordKey, now)
}

// publishedSessionTestAllows reports an outage allow for key.
func publishedSessionTestAllows(root, identity string, key SessionKey) bool {
	got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
	return err == nil && !got.Deny
}

func publishedSessionTestKey(t *testing.T, root string) SessionRecordKey {
	t.Helper()
	key, err := ReadPublishedSessionKey(root)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// GAP-0352: the gateway's answer for every session exchange is written to
// the protected records, and during an outage only the records of the
// agent process and the session, under the current key, let a call go on.
func TestPublishedForeignHookSessionRecordRoundTrip(t *testing.T) {
	root := publishedSessionTestRoot(t)
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
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(key, trustAll); err != nil || got.Deny {
		t.Fatalf("an allowed process and session must be proven unblocked: %+v %v", got, err)
	}
	reason := foreignHookBlockedPrefix + " When this agent session started, the project hook file /repo/.github/hooks/x.json defined a hook."
	if err := publishCurrent(root, identity, key, GuardDecision{Deny: true, Reason: reason}, time.Now()); err != nil {
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
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
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
	// A record or key file that fails the trust check blocks.
	recordKey := publishedSessionTestKey(t, root)
	for _, refused := range []string{"", recordKey.ID()} {
		trust := func(path string) error {
			if refused == "" || path == refused {
				return errors.New("writable by the user")
			}
			return nil
		}
		if _, err := check(key, trust); !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("an untrusted record or key (%q) must prove nothing: %v", refused, err)
		}
	}
	path, ok := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	if !ok {
		t.Fatal("no record path")
	}
	canonical, _ := connector.CanonicalUserScopedIdentity(identity)
	at := time.Now().UTC().Format(time.RFC3339)
	encode := func(record PublishedSessionRecord, macIdentity string) string {
		t.Helper()
		record.MAC = publishedSessionMAC(recordKey.secret, macIdentity, record)
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	good := PublishedSessionRecord{Version: publishedSessionVersion, Connector: "copilot", Kind: sessionKindProcess, ID: key.Process, At: at}
	// The writer's own encoding of the same record proves the process: the
	// cases below differ from it in one point each.
	if err := os.WriteFile(path, []byte(encode(good, canonical)), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := check(key, trustAll); err != nil || got.Deny {
		t.Fatalf("a well-formed record must prove the process: %+v %v", got, err)
	}
	withID, withVersion, withAt := good, good, good
	withID.ID, withVersion.Version, withAt.At = "linux:b:9:9", 2, ""
	tampered := encode(good, canonical)
	tampered = strings.Replace(tampered, `"at":"`+at+`"`, `"at":"`+time.Now().Add(time.Second).UTC().Format(time.RFC3339)+`"`, 1)
	for name, content := range map[string]string{
		"corrupt":           `{"v":3,"connector":"copilot"`,
		"unknown field":     strings.TrimSuffix(encode(good, canonical), "}") + `,"x":1}`,
		"other key":         encode(withID, canonical),
		"other version":     encode(withVersion, canonical),
		"no time":           encode(withAt, canonical),
		"no MAC":            strings.Replace(encode(good, canonical), `,"mac":"`, `,"x":"`, 1),
		"another account":   encode(good, publishedSessionOtherIdentity(canonical)),
		"a changed field":   tampered,
		"trailing value":    encode(good, canonical) + ` {}`,
		"an earlier schema": `{"v":2,"connector":"copilot","kind":"p","id":"` + key.Process + `","blocked":false,"at":"` + at + `","gen":"1"}`,
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := check(key, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("%s: the record must prove nothing: %v", name, err)
		}
	}
	// Review P2: a session record alone proves nothing. An agent process the
	// hook cannot name may be one that started during the outage and
	// resumed the session ID, and a named one needs its own record.
	unnamed := SessionKey{Connector: "copilot", Session: "u-1"}
	if err := publishCurrent(root, identity, unnamed, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(unnamed, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) || got.Deny {
		t.Fatalf("an unnamed process must not be proven by a clean session record: %+v %v", got, err)
	}
	if _, err := check(SessionKey{Connector: "copilot", Session: "u-1", Process: "linux:b:3:100"}, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a named process without its own record must not be proven by the session: %v", err)
	}
}

// Kill switch (1.0.4 guard loop round 1): an outage allow needs the record
// of every key part the call names. A process allowed in one session is
// not allowed in a session the gateway never answered for under the
// current key (a new one, or one whose record a block left or a removal
// ended), so a block whose publication failed for the session cannot leave
// another process's allow usable in it.
func TestPublishedForeignHookSessionNeedsTheRecordOfTheSessionToo(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	own := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-2"}
	if err := publishCurrent(root, identity, own, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionTestAllows(root, identity, own) {
		t.Fatal("the process in its own session must be allowed")
	}
	resumed := SessionKey{Connector: "copilot", Session: "s-9", Process: own.Process}
	if publishedSessionTestAllows(root, identity, resumed) {
		t.Fatal("a session with no record must not be allowed on the process record alone")
	}
	// The session record of an earlier key is dead too.
	if err := publishCurrent(root, identity, SessionKey{Connector: "copilot", Session: resumed.Session}, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := CreatePublishedSessionKey(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if err := publishCurrent(root, identity, SessionKey{Connector: "copilot", Process: own.Process}, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if publishedSessionTestAllows(root, identity, resumed) {
		t.Fatal("a session record of an earlier key must not prove the session")
	}
	// A blocking session record denies a process that is allowed elsewhere.
	if err := publishCurrent(root, identity, SessionKey{Connector: "copilot", Session: resumed.Session}, GuardDecision{Deny: true}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := CheckPublishedForeignHookSession(root, identity, resumed, GuardDecision{}, trustAll); err != nil || !got.Deny {
		t.Fatalf("a blocked session must deny: %+v %v", got, err)
	}
}

// Kill switch: removing the key ends every allow, of every connector and
// account, with no record found or deleted. An allow published while there
// is no key proves nothing, and neither does any record after a new key:
// only the next exchange under it proves the process again. Killing what is
// gone is no error.
func TestKillPublishedSessionKeyEndsEveryEarlierAllow(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	other := publishedSessionOtherIdentity(identity)
	copilot := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	opencode := SessionKey{Connector: "opencode", Session: "o-1", Process: "p-1"}
	publish := func() {
		t.Helper()
		for _, account := range []string{identity, other} {
			for _, key := range []SessionKey{copilot, opencode} {
				if err := publishCurrent(root, account, key, GuardDecision{}, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	allowed := func() int {
		count := 0
		for _, account := range []string{identity, other} {
			for _, key := range []SessionKey{copilot, opencode} {
				if publishedSessionTestAllows(root, account, key) {
					count++
				}
			}
		}
		return count
	}
	publish()
	if got := allowed(); got != 4 {
		t.Fatalf("every published allow must prove its process: %d", got)
	}
	if err := KillPublishedSessionKey(root); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublishedSessionKey(root); err == nil {
		t.Fatal("no key may be left")
	}
	if got := allowed(); got != 0 {
		t.Fatalf("the kill must end every earlier allow: %d", got)
	}
	publish()
	if got := allowed(); got != 0 {
		t.Fatalf("an allow published without a key must prove nothing: %d", got)
	}
	if err := KillPublishedSessionKey(root); err != nil {
		t.Fatalf("killing what is gone is no error: %v", err)
	}
	if err := CreatePublishedSessionKey(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if got := allowed(); got != 0 {
		t.Fatalf("a new key must not bring an earlier allow back: %d", got)
	}
	publish()
	if got := allowed(); got != 4 {
		t.Fatalf("the allows of the new key must prove their processes: %d", got)
	}
	// A new key while one exists replaces it: one key, and the allows of
	// the old one are dead.
	before := publishedSessionTestKey(t, root)
	if err := CreatePublishedSessionKey(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if after := publishedSessionTestKey(t, root); after.ID() == before.ID() {
		t.Fatal("a new key must have a new name")
	}
	if got := allowed(); got != 0 {
		t.Fatalf("a new key must end the allows of the one it replaced: %d", got)
	}
}

// Kill switch: any failure to rotate the key blocks. A key file that cannot
// be removed fails the kill; root or SYSTEM then adds a second key, and the
// hook trusts no folder with more than one. A key that cannot be created
// leaves none. A key folder that cannot be listed, a key owner that cannot
// be read, more than one key, or one whose name is not a key's all block.
func TestPublishedSessionKeyRotationFailureBlocks(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	allow := func() {
		t.Helper()
		if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	allow()
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("the allow must prove the process")
	}

	// The key file cannot be removed.
	stuck := publishedSessionTestKey(t, root).ID()
	previousRemove := publishedSessionRemoveKey
	publishedSessionRemoveKey = func(name string) error {
		if name == stuck {
			return &os.PathError{Op: "remove", Path: name, Err: errors.New("the file is in use")}
		}
		return previousRemove(name)
	}
	t.Cleanup(func() { publishedSessionRemoveKey = previousRemove })
	if err := KillPublishedSessionKey(root); err == nil {
		t.Fatal("a kill that leaves the key must fail")
	}
	if err := RetirePublishedSessionKey(root, publishedSessionTestTrust); err == nil || !strings.Contains(err.Error(), "a second key was added") {
		t.Fatalf("root must add a second key when it cannot remove the first: %v", err)
	}
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a folder with two keys must prove nothing")
	}
	allow()
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("an allow published while the folder has two keys must prove nothing")
	}
	if err := CreatePublishedSessionKey(root, publishedSessionTestTrust); err == nil {
		t.Fatal("a new key that cannot replace the stuck one must report it")
	}
	allow()
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("the stuck key must keep the folder ambiguous")
	}
	publishedSessionRemoveKey = previousRemove
	if err := EnsurePublishedSessionKey(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stuck); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the next run must remove the stuck key: %v", err)
	}
	allow()
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("one key again must prove the next allow")
	}

	// The new key cannot be created: the kill took, so nothing proves.
	previousCreate := publishedSessionCreateKeyFile
	publishedSessionCreateKeyFile = func(string, PublishedSessionTrust) error { return errors.New("no space left on device") }
	if err := CreatePublishedSessionKey(root, publishedSessionTestTrust); err == nil {
		t.Fatal("a key that cannot be created must be reported")
	}
	publishedSessionCreateKeyFile = previousCreate
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("no key must prove nothing")
	}
	if err := CreatePublishedSessionKey(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	allow()

	// The key folder cannot be listed, or a key owner cannot be read.
	previousList := publishedSessionList
	publishedSessionList = func(string) ([]string, error) { return nil, errors.New("input/output error") }
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a key folder that cannot be listed must prove nothing")
	}
	if err := KillPublishedSessionKey(root); err == nil {
		t.Fatal("a kill that cannot list the key folder must fail")
	}
	publishedSessionList = previousList
	restore := OverridePublishedSessionKeyOwnerForTest(func(string) (bool, error) { return false, errors.New("access denied") })
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a key owner that cannot be read must prove nothing")
	}
	restore()
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("the allow must prove the process again")
	}

	// A name with the key prefix that is not a key's is no key at all.
	dir, _ := PublishedSessionKeyDir(root)
	current := publishedSessionTestKey(t, root).ID()
	upper := filepath.Join(dir, filepath.Base(root)+PublishedSessionKeyInfix+strings.ToUpper(strings.TrimPrefix(filepath.Base(current), filepath.Base(root)+PublishedSessionKeyInfix)))
	names := []string{filepath.Join(dir, filepath.Base(root)+PublishedSessionKeyInfix+"abc")}
	if runtime.GOOS != "windows" {
		// Windows file names ignore case: there it is the key itself.
		names = append(names, upper)
	}
	for _, name := range names {
		if err := os.WriteFile(name, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := publishedSessionTestKey(t, root); got.ID() != current {
		t.Fatalf("a name that is not a key's must be skipped: %s", got.ID())
	}
}

// Kill switch: a file with a key's name that root, SYSTEM or
// Administrators did not make is not a key. On Windows a standard user may
// create one in %ProgramData%\Cisco: it neither counts as a second key (one
// account must not block every other account's outage allows) nor proves
// anything on its own.
func TestPublishedSessionKeyOfAnotherAccountIsNoKey(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	dir, prefix, _ := publishedSessionKeyPlace(root)
	planted := filepath.Join(dir, prefix+strings.Repeat("ab", publishedSessionKeyBytes))
	if err := os.WriteFile(planted, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	withPublishedSessionKeysOfTheTestAccount(t, planted)
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a planted key file must not block the real key")
	}
	if err := KillPublishedSessionKey(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(planted); err != nil {
		t.Fatalf("the kill only removes keys: %v", err)
	}
	// The planted name alone, even with a record MACed under it, proves
	// nothing: the hook finds no key.
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, SessionRecordKey{path: planted, secret: []byte(strings.Repeat("\xab", publishedSessionKeyBytes))}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a key another account made must prove nothing")
	}
}

// Review fixes (round 3 scenario 4, kill switch): a repair cannot rely on
// replacing the record folder. An account that kept a way to change it (a
// retained Windows handle with WRITE_DAC, a macOS access-list entry) may put
// the earlier records back, folder and all, after the repair, and even a
// file with the earlier key's name. None of it counts: the repair retired
// the key first, and only root or SYSTEM can give a file a key's name that
// the hook accepts.
func TestPublishedSessionRecordsPutBackAfterARepairProveNothing(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	old := publishedSessionTestKey(t, root).ID()
	dir, _ := PublishedSessionIdentityDir(root, identity)
	saved := filepath.Join(t.TempDir(), "saved")
	if err := os.CopyFS(saved, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	// The repair: the key is retired before anything else, and a new one
	// made once the run succeeded.
	if err := RetirePublishedSessionKey(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if err := CreatePublishedSessionKey(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	// The account puts its old folder back, and a file with the old key's
	// name that it made itself.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(dir, os.DirFS(saved)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	withPublishedSessionKeysOfTheTestAccount(t, old)
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("records put back after a repair must prove nothing")
	}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("the next exchange under the new key must prove the process")
	}
}

// The guardian makes sure there is a key at every pass: none or more than
// one gets one new key, one is kept, and a missing record folder gets none.
func TestEnsurePublishedSessionKey(t *testing.T) {
	root := publishedSessionTestRoot(t)
	first := publishedSessionTestKey(t, root).ID()
	if err := EnsurePublishedSessionKey(root, publishedSessionTestTrust); err != nil || publishedSessionTestKey(t, root).ID() != first {
		t.Fatalf("one key must be kept: %v", err)
	}
	if err := KillPublishedSessionKey(root); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePublishedSessionKey(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	second := publishedSessionTestKey(t, root).ID()
	if second == first {
		t.Fatal("a missing key must be replaced by a new one")
	}
	if _, err := createPublishedSessionKey(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublishedSessionKey(root); err == nil {
		t.Fatal("two keys must be no key")
	}
	if err := EnsurePublishedSessionKey(root, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if third := publishedSessionTestKey(t, root).ID(); third == second {
		t.Fatal("two keys must be replaced by one new one")
	}
	missing := filepath.Join(t.TempDir(), "sessions")
	if err := EnsurePublishedSessionKey(missing, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	if keys, err := publishedSessionKeys(missing); err != nil || len(keys) != 0 {
		t.Fatalf("a missing record folder gets no key: %v %v", keys, err)
	}
	if err := RemovePublishedSessionKeys(root); err != nil {
		t.Fatal(err)
	}
	if keys, err := publishedSessionKeys(root); err != nil || len(keys) != 0 {
		t.Fatalf("uninstall must remove every key: %v %v", keys, err)
	}
}

// Review P1 (round 3, kept): a record folder on a volume that is read-only
// proves nothing, since no key could be removed there; one whose state
// cannot be read neither. A block still denies.
func TestPublishedForeignHookSessionOnAReadOnlyVolumeProvesNothing(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if readOnly, err := publishedSessionVolumeIsReadOnly(root); err != nil || readOnly {
		t.Fatalf("a temporary folder is on a writable volume: %v %v", readOnly, err)
	}
	previous := publishedSessionVolumeReadOnly
	t.Cleanup(func() { publishedSessionVolumeReadOnly = previous })
	for name, state := range map[string]func(string) (bool, error){
		"read-only":  func(string) (bool, error) { return true, nil },
		"unreadable": func(string) (bool, error) { return false, errors.New("statfs failed") },
	} {
		publishedSessionVolumeReadOnly = state
		if publishedSessionTestAllows(root, identity, key) {
			t.Fatalf("%s: the allow must prove nothing", name)
		}
	}
	if err := publishCurrent(root, identity, key, GuardDecision{Deny: true}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll); err != nil || !got.Deny {
		t.Fatalf("a block must still deny: %+v %v", got, err)
	}
}

// The key is read again at the end of the check: a kill while the check
// runs ends the allow it was reading.
func TestPublishedForeignHookSessionKeyKilledDuringTheCheck(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	previous := publishedSessionVolumeReadOnly
	t.Cleanup(func() { publishedSessionVolumeReadOnly = previous })
	for name, during := range map[string]func(){
		"killed":   func() { _ = KillPublishedSessionKey(root) },
		"replaced": func() { _ = CreatePublishedSessionKey(root, publishedSessionTestTrust) },
	} {
		if err := CreatePublishedSessionKey(root, publishedSessionTestTrust); err != nil {
			t.Fatal(err)
		}
		if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
		publishedSessionVolumeReadOnly = func(path string) (bool, error) {
			during()
			return false, nil
		}
		if publishedSessionTestAllows(root, identity, key) {
			t.Fatalf("%s during the check: the allow must prove nothing", name)
		}
		publishedSessionVolumeReadOnly = previous
	}
}

// Without a root nothing is written.
func TestPublishedForeignHookSessionWithoutARootWritesNothing(t *testing.T) {
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := PublishForeignHookSessionDecision("", identity, key, GuardDecision{}, SessionRecordKey{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if err := PublishForeignHookSessionDecision(missing, identity, key, GuardDecision{}, SessionRecordKey{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a missing root must not be created")
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
		mod := now.Add(-time.Duration(publishedSessionDirLimit+5-i) * time.Millisecond)
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	old := filepath.Join(dir, "copilot-s-old.json")
	if err := os.WriteFile(old, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := now.Add(-publishedSessionMaxAge - time.Minute)
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
		t.Fatal("a record past its age must be pruned")
	}
}
