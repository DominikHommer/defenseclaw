// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// foreignHookPublished is one protected record write of the gateway: keyID
// names the key its MAC was made with ("" for none).
type foreignHookPublished struct {
	root, identity string
	key            enterprisepolicy.SessionKey
	deny           bool
	keyID          string
}

// foreignHookTestTrust names the gateway service for the test record key.
var foreignHookTestTrust = enterprisepolicy.PublishedSessionTrust{ServiceAccount: `NT SERVICE\` + managed.StandaloneWindowsGatewaySvc}

func foreignHookRecorder(writes *[]foreignHookPublished, result func() error) func(string, string, enterprisepolicy.SessionKey, enterprisepolicy.GuardDecision, enterprisepolicy.SessionRecordKey, time.Time) error {
	return func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, _ time.Time) error {
		*writes = append(*writes, foreignHookPublished{r, identity, key, decision.Deny, recordKey.ID()})
		if result != nil {
			return result()
		}
		return nil
	}
}

// GAP-0352: every session exchange of a standalone gateway writes its answer
// into the caller's protected session record, for the verified caller only:
// a block for the session start that found an unapproved hook, the block it
// then enforces, and the allow of another account. The block removed the
// key before it was recorded, so the allow published after it carries no
// key until the guardian makes a new one, and then carries that one.
func TestForeignHookSessionGatewayPublishesTheProtectedRecord(t *testing.T) {
	var writes []foreignHookPublished
	server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
	first := server.keyID()
	if first == "" {
		t.Fatal("the test record folder has no key")
	}
	alice, bob := server.alice, server.bob
	key := map[string]any{"connector": "claudecode", "session": "s-1", "process": "process-1"}
	server.call(server.aliceToken, map[string]any{"key": key, "session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}}})
	if server.keyID() != "" {
		t.Fatal("the block must remove the key")
	}
	server.call(server.aliceToken, map[string]any{"key": key, "decision": map[string]any{"deny": false}})
	server.call(server.bobToken, map[string]any{"key": key, "decision": map[string]any{"deny": false}})
	server.newKey()
	second := server.keyID()
	server.call(server.bobToken, map[string]any{"key": key, "decision": map[string]any{"deny": false}})
	root := server.root
	sessionKey := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: "process-1"}
	want := []foreignHookPublished{
		{root, alice, sessionKey, true, ""},
		{root, alice, sessionKey, true, ""},
		{root, bob, sessionKey, false, ""},
		{root, bob, sessionKey, false, second},
	}
	if len(writes) != len(want) {
		t.Fatalf("published %+v, want %+v", writes, want)
	}
	for i := range want {
		if writes[i] != want[i] {
			t.Fatalf("publish %d = %+v, want %+v", i, writes[i], want[i])
		}
	}
}

// Kill switch (GAP-0352): the gateway reads the record key before the
// guardian's removals, and the guardian removes the key before it records a
// removal and makes a new one after, so no interleaving leaves an allow
// that a removal should have ended:
//   - the guardian records after the gateway read the ledger, before the
//     exchange answers: the allow it published first (from the earlier
//     ledger) carries the key the guardian removed, so the hook refuses it,
//     and the exchange reads the removals again before it answers, so this
//     call is denied too and the denial is published after a kill;
//   - the guardian records after the gateway read the key, before the
//     ledger: the exchange reads the new ledger and is denied;
//   - the guardian rewrites the ledger in place, keeping its file, time and
//     size, and makes a new key: the cached ledger is read again because the
//     key changed.
func TestForeignHookSessionGatewayUsesTheKeyItReadBeforeTheRemovals(t *testing.T) {
	var writes []foreignHookPublished
	var afterRead func()
	server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
	early := runtime.GOOS + ":b:1:100"
	allow := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": early}, "decision": map[string]any{"deny": false}}
	last := func() foreignHookPublished {
		t.Helper()
		if len(writes) == 0 {
			t.Fatal("nothing was published")
		}
		return writes[len(writes)-1]
	}

	// After the ledger read: the publish runs the guardian first.
	previous := foreignHookSessionPublish
	foreignHookSessionPublish = func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, now time.Time) error {
		if afterRead != nil {
			afterRead()
			afterRead = nil
		}
		return previous(r, identity, key, decision, recordKey, now)
	}
	t.Cleanup(func() { foreignHookSessionPublish = previous })
	afterRead = func() { server.guardian(server.alice, "/home/alice/.claude/settings.json") }
	before := server.keyID()
	if got := server.call(server.aliceToken, allow); !got.Deny || !strings.Contains(got.Reason, "started before DefenseClaw removed") {
		t.Fatalf("an exchange whose removal the guardian recorded before it answered must be denied: %+v", got)
	}
	if len(writes) < 2 {
		t.Fatalf("the allow and the denial that replaces it must both be published: %+v", writes)
	}
	if published := writes[len(writes)-2]; published.deny || published.keyID != before || published.keyID == server.keyID() {
		t.Fatalf("its first allow must carry the key the guardian removed (%s, now %s): %+v", before, server.keyID(), published)
	}
	if published := last(); !published.deny || server.keyID() != "" {
		t.Fatalf("the denial that replaces it is published after a kill: %+v (key %q)", published, server.keyID())
	}
	server.newKey()
	if got := server.call(server.aliceToken, allow); !got.Deny || !strings.Contains(got.Reason, "started before DefenseClaw removed") {
		t.Fatalf("the next exchange must be denied: %+v", got)
	}

	// After the key read, before the ledger read.
	if err := os.Remove(filepath.Join(server.guardianDir, enterprisepolicy.ForeignHookRemovalsFile)); err != nil {
		t.Fatal(err)
	}
	server.newKey()
	if got := server.call(server.aliceToken, allow); got.Deny {
		t.Fatalf("no ledger allows: %+v", got)
	}
	previousKey := foreignHookSessionKey
	foreignHookSessionKey = func(r string) (enterprisepolicy.SessionRecordKey, error) {
		key, err := previousKey(r)
		foreignHookSessionKey = previousKey
		server.guardian(server.alice, "/home/alice/.claude/settings.json")
		return key, err
	}
	t.Cleanup(func() { foreignHookSessionKey = previousKey })
	if got := server.call(server.aliceToken, allow); !got.Deny {
		t.Fatalf("an exchange that read the key before the guardian's removal reads the new ledger and is denied: %+v", got)
	}

	// The cached ledger follows the key, whatever the file says.
	ledgerPath := filepath.Join(server.guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	other := server.encode(server.bob, "/home/x/.claude/settings.json")
	mine := server.encode(server.alice, "/home/x/.claude/settings.json")
	if len(other) != len(mine) {
		t.Fatalf("the two ledgers must have one size: %d %d", len(other), len(mine))
	}
	if err := os.WriteFile(ledgerPath, other, 0o640); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(-time.Minute).Truncate(time.Second)
	if err := os.Chtimes(ledgerPath, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	server.newKey()
	if got := server.call(server.aliceToken, allow); got.Deny {
		t.Fatalf("another account's removal must not deny: %+v", got)
	}
	file, err := os.OpenFile(ledgerPath, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(mine); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(ledgerPath, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	server.newKey()
	if got := server.call(server.aliceToken, allow); !got.Deny {
		t.Fatalf("a ledger rewritten in place before a new key must be read again: %+v", got)
	}
}

// foreignHookPublishTestServer is a standalone user-scoped gateway with two
// enrolled accounts whose protected-record writes go to publish. Its record
// folder has a key the test account made.
type foreignHookPublishTestServer struct {
	alice, bob           string
	aliceToken, bobToken string
	guardianDir          string
	dataDir              string
	root                 string
	call                 func(token string, update map[string]any) enterprisepolicy.GuardDecision
	t                    *testing.T
}

// keyID names the record folder's current key ("" for none).
func (s *foreignHookPublishTestServer) keyID() string {
	key, err := foreignHookSessionKey(s.root)
	if err != nil {
		return ""
	}
	return key.ID()
}

// newKey makes a new record key, as the guardian and the lifecycle do.
func (s *foreignHookPublishTestServer) newKey() {
	s.t.Helper()
	if err := enterprisepolicy.CreatePublishedSessionKey(s.root, foreignHookTestTrust); err != nil {
		s.t.Fatal(err)
	}
}

// encode is a removal ledger with one removal of identity's file.
func (s *foreignHookPublishTestServer) encode(identity, file string) []byte {
	s.t.Helper()
	now := time.Now().UTC()
	data, _, err := enterprisepolicy.EncodeForeignHookRemovals(nil, []enterprisepolicy.ForeignHookRemoval{{
		Identity: identity, Connector: "claudecode", Path: file, At: now.Format(time.RFC3339), Mark: runtime.GOOS + ":b:200",
	}}, now)
	if err != nil {
		s.t.Fatal(err)
	}
	return data
}

// ledger replaces the removal ledger with one removal of identity's file.
func (s *foreignHookPublishTestServer) ledger(identity, file string) {
	s.t.Helper()
	path := filepath.Join(s.guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	if err := os.WriteFile(path+".tmp", s.encode(identity, file), 0o640); err != nil {
		s.t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		s.t.Fatal(err)
	}
}

// guardian records a removal the way the guardian does: the key goes
// first, then the ledger, then a new key.
func (s *foreignHookPublishTestServer) guardian(identity, file string) {
	s.t.Helper()
	if err := enterprisepolicy.KillPublishedSessionKey(s.root); err != nil {
		s.t.Fatal(err)
	}
	s.ledger(identity, file)
	s.newKey()
}

func newForeignHookPublishTestServer(t *testing.T, publish func(string, string, enterprisepolicy.SessionKey, enterprisepolicy.GuardDecision, enterprisepolicy.SessionRecordKey, time.Time) error) *foreignHookPublishTestServer {
	t.Helper()
	root := filepath.Join(t.TempDir(), "sessions")
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal(err)
	}
	server := &foreignHookPublishTestServer{root: root, t: t}
	ledger := &userScopedTestLedger{}
	alice, bob := "1001", "1002"
	if runtime.GOOS == "windows" {
		alice, bob = "S-1-5-21-1111-2222-3333-1001", "S-1-5-21-1111-2222-3333-1002"
		ledger.set(
			managedHookLedgerTarget{User: "alice", SID: alice, Connector: "claudecode", OK: true},
			managedHookLedgerTarget{User: "bob", SID: bob, Connector: "claudecode", OK: true},
		)
	} else {
		ledger.set(
			managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001), Connector: "claudecode", OK: true},
			managedHookLedgerTarget{User: "bob", UID: userScopedTestUID(1002), Connector: "claudecode", OK: true},
		)
	}
	server.alice, server.bob = alice, bob
	server.guardianDir = t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, server.guardianDir)
	restoreValidate := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	// The gateway accepts only root's, SYSTEM's or Administrators' keys; the
	// test account made this one.
	restoreOwner := enterprisepolicy.OverridePublishedSessionKeyOwnerForTest(func(path string) (bool, error) {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return info.Mode().IsRegular(), nil
	})
	previousRoot, previousPublish, previousKey, previousKill := foreignHookSessionPublishRoot, foreignHookSessionPublish, foreignHookSessionKey, foreignHookSessionKill
	foreignHookSessionPublishRoot = func() (string, error) { return root, nil }
	foreignHookSessionPublish = publish
	t.Cleanup(func() {
		validateManagedGuardianAuthorization = restoreValidate
		restoreOwner()
		foreignHookSessionPublishRoot, foreignHookSessionPublish, foreignHookSessionKey, foreignHookSessionKill = previousRoot, previousPublish, previousKey, previousKill
	})
	server.newKey()
	api, _, _ := newUserScopedTestServer(t, true, ledger, map[string]string{alice: "alice", bob: "bob"})
	if api.scannerCfg == nil || !api.scannerCfg.StandaloneEnterprise() {
		t.Skip("the user-scoped test server is not a standalone deployment")
	}
	server.dataDir = api.configDataDir()
	handler := api.tokenAuth(api.managedHookSocketMux())
	aliceToken := userScopedTestToken(t, connector.UserScopedHookCredential, "claudecode", alice)
	bobToken := userScopedTestToken(t, connector.UserScopedHookCredential, "claudecode", bob)
	server.aliceToken, server.bobToken = aliceToken, bobToken
	peerUIDs := map[string]int{aliceToken: 1001, bobToken: 1002}
	server.call = func(token string, update map[string]any) enterprisepolicy.GuardDecision {
		t.Helper()
		data, err := json.Marshal(update)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", bytes.NewReader(data))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "foreign-hook-guard/1.0")
		req.Header.Set("Authorization", "Bearer "+token)
		req = req.WithContext(context.WithValue(req.Context(), acpConnPeerKey{}, &acpConnPeer{uid: peerUIDs[token], known: true}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("exchange: %d %s", response.Code, response.Body.String())
		}
		var decision enterprisepolicy.GuardDecision
		if err := json.Unmarshal(response.Body.Bytes(), &decision); err != nil {
			t.Fatalf("exchange answer %q: %v", response.Body.String(), err)
		}
		return decision
	}
	return server
}

// Review P2 (GAP-0352, loop round 2; loop round 3): while the guardian holds
// an account closed because it could not record a removal, every guarded
// call of the account is denied and only blocks are published; another
// account is not affected, and the account is allowed again once the mark
// is cleared. The mark is on the account's private session store, so an
// account that deletes or moves its folder of protected records, or empties
// the record root, does not clear it.
func TestForeignHookSessionGatewayDeniesAnAccountWhoseRemovalIsPending(t *testing.T) {
	var writes []foreignHookPublished
	server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
	accountDir, _ := enterprisepolicy.PublishedSessionIdentityDir(server.root, server.alice)
	if err := os.MkdirAll(accountDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := enterprisepolicy.MarkForeignHookRemovalPending(server.dataDir, server.alice); err != nil {
		t.Fatal(err)
	}
	allow := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": runtime.GOOS + ":b:1:500"}, "decision": map[string]any{"deny": false}}
	if got := server.call(server.aliceToken, allow); !got.Deny || !strings.Contains(got.Reason, "could not record the removal yet") {
		t.Fatalf("a held account must be denied: %+v", got)
	}
	if err := os.RemoveAll(accountDir); err != nil {
		t.Fatal(err)
	}
	if got := server.call(server.aliceToken, allow); !got.Deny || !strings.Contains(got.Reason, "could not record the removal yet") {
		t.Fatalf("a held account whose record folder is gone must still be denied: %+v", got)
	}
	server.newKey()
	if got := server.call(server.bobToken, allow); got.Deny {
		t.Fatalf("another account must be allowed: %+v", got)
	}
	if err := enterprisepolicy.ClearForeignHookRemovalPending(server.dataDir, server.alice); err != nil {
		t.Fatal(err)
	}
	if got := server.call(server.aliceToken, allow); got.Deny {
		t.Fatalf("the account must be allowed once the mark is cleared: %+v", got)
	}
	var got []string
	for _, w := range writes {
		got = append(got, w.identity+" deny="+map[bool]string{true: "true", false: "false"}[w.deny])
	}
	want := []string{server.alice + " deny=true", server.alice + " deny=true", server.bob + " deny=false", server.alice + " deny=false"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("published %v, want %v", got, want)
	}
}

// Review P2 (GAP-0352, loop round 3): a standalone gateway that cannot
// locate its protected session record folder at all denies the exchange:
// it can neither remove the key nor publish its answer. Nothing is
// published, the account's pending mark keeps its own reason, and the
// exchange is allowed again once the folder is found. A record folder whose
// key cannot be read is published to without a key, so the allow proves
// nothing during an outage.
func TestForeignHookSessionGatewayDeniesWhenTheRecordFolderCannotBeLocated(t *testing.T) {
	var writes []foreignHookPublished
	server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
	previousDataDir := foreignHookSessionRootForDataDir
	foreignHookSessionRootForDataDir = func(string) (string, bool) { return "", false }
	t.Cleanup(func() { foreignHookSessionRootForDataDir = previousDataDir })
	lookupErr := errors.New("the protected ProgramData registration cannot be read")
	foreignHookSessionPublishRoot = func() (string, error) {
		if lookupErr != nil {
			return "", lookupErr
		}
		return server.root, nil
	}
	allow := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": runtime.GOOS + ":b:1:500"}, "decision": map[string]any{"deny": false}}
	if got := server.call(server.aliceToken, allow); !got.Deny || !strings.Contains(got.Reason, "cannot verify") {
		t.Fatalf("an exchange without its record folder must be denied: %+v", got)
	}
	if err := enterprisepolicy.MarkForeignHookRemovalPending(server.dataDir, server.alice); err != nil {
		t.Fatal(err)
	}
	if got := server.call(server.aliceToken, allow); !got.Deny || !strings.Contains(got.Reason, "could not record the removal yet") {
		t.Fatalf("the pending mark must deny with its own reason: %+v", got)
	}
	if len(writes) != 0 {
		t.Fatalf("nothing can be published without the folder: %+v", writes)
	}
	if err := enterprisepolicy.ClearForeignHookRemovalPending(server.dataDir, server.alice); err != nil {
		t.Fatal(err)
	}
	lookupErr = nil
	if got := server.call(server.aliceToken, allow); got.Deny || len(writes) != 1 || writes[0].keyID != server.keyID() || writes[0].keyID == "" {
		t.Fatalf("once the folder is found the exchange is allowed and published with the key: %+v %+v", got, writes)
	}
	foreignHookSessionKey = func(string) (enterprisepolicy.SessionRecordKey, error) {
		return enterprisepolicy.SessionRecordKey{}, errors.New("the key file is not root's")
	}
	if got := server.call(server.aliceToken, allow); got.Deny || len(writes) != 2 || writes[1].keyID != "" {
		t.Fatalf("without a key the allow is published without one: %+v %+v", got, writes)
	}
}

// Review P2 (GAP-0352, 1.0.4 loop round 4): the guardian records a removal
// after an exchange read the removals and before it answers. The exchange
// reads the key and the removals again before it answers, so every way the
// guardian records one denies this call, and the denial, published after a
// kill, is the record the hook finds: a ledger write between a kill and a
// new key, a pending mark (a ledger write that failed), and a ledger write
// the guardian made no new key after yet. A removal for another account, or
// a new key alone, keeps the allow, published again with the new key. With
// nothing recorded, or a denial from the scan, the exchange publishes once.
func TestForeignHookSessionGatewayRechecksTheRemovalsBeforeItAnswers(t *testing.T) {
	process := runtime.GOOS + ":b:1:100"
	allow := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": process}, "decision": map[string]any{"deny": false}}
	deny := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-2", "process": process},
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: unverifiable hook"}}
	kill := func(s *foreignHookPublishTestServer) {
		if err := enterprisepolicy.KillPublishedSessionKey(s.root); err != nil {
			s.t.Fatal(err)
		}
	}
	mark := func(s *foreignHookPublishTestServer) {
		if err := enterprisepolicy.MarkForeignHookRemovalPending(s.dataDir, s.alice); err != nil {
			s.t.Fatal(err)
		}
	}
	const file = "/home/x/.claude/settings.json"
	for _, c := range []struct {
		name     string
		guardian func(s *foreignHookPublishTestServer)
		update   map[string]any
		deny     string // the reason the answer must carry, "" for an allow
		writes   int
	}{
		{name: "ledger and a new key", guardian: func(s *foreignHookPublishTestServer) { s.guardian(s.alice, file) }, update: allow, deny: "started before DefenseClaw removed", writes: 2},
		{name: "pending mark and a new key", guardian: func(s *foreignHookPublishTestServer) { kill(s); mark(s); s.newKey() }, update: allow, deny: "could not record the removal yet", writes: 2},
		{name: "pending mark, no new key", guardian: func(s *foreignHookPublishTestServer) { kill(s); mark(s) }, update: allow, deny: "could not record the removal yet", writes: 2},
		{name: "ledger, no new key yet", guardian: func(s *foreignHookPublishTestServer) { kill(s); s.ledger(s.alice, file) }, update: allow, deny: "started before DefenseClaw removed", writes: 2},
		{name: "another account's removal", guardian: func(s *foreignHookPublishTestServer) { s.guardian(s.bob, file) }, update: allow, writes: 2},
		{name: "a new key alone", guardian: func(s *foreignHookPublishTestServer) { s.newKey() }, update: allow, writes: 2},
		{name: "nothing recorded", guardian: func(*foreignHookPublishTestServer) {}, update: allow, writes: 1},
		{name: "a denial from the scan", guardian: func(s *foreignHookPublishTestServer) { s.guardian(s.alice, file) }, update: deny, deny: "unverifiable hook", writes: 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			var writes []foreignHookPublished
			var server *foreignHookPublishTestServer
			ran := false
			server = newForeignHookPublishTestServer(t, func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, _ time.Time) error {
				writes = append(writes, foreignHookPublished{r, identity, key, decision.Deny, recordKey.ID()})
				if !ran {
					// The guardian runs after the exchange decided, before
					// it answers.
					ran = true
					c.guardian(server)
				}
				return nil
			})
			before := server.keyID()
			scanDenies := c.update["decision"].(map[string]any)["deny"] == true
			got := server.call(server.aliceToken, c.update)
			if c.deny == "" && got.Deny || c.deny != "" && (!got.Deny || !strings.Contains(got.Reason, c.deny)) {
				t.Fatalf("answer %+v, want deny reason %q", got, c.deny)
			}
			if len(writes) != c.writes {
				t.Fatalf("published %+v, want %d writes", writes, c.writes)
			}
			if first := writes[0]; first.deny != scanDenies || !scanDenies && first.keyID != before {
				t.Fatalf("the first record is the exchange's own answer, with the key it read first: %+v (key %s)", first, before)
			}
			final := writes[len(writes)-1]
			if final.deny != got.Deny || !got.Deny && len(writes) > 1 && final.keyID != server.keyID() {
				t.Fatalf("the last record is the answer, with the current key %s: %+v", server.keyID(), final)
			}
			if got.Deny && !scanDenies && server.keyID() != "" {
				t.Fatalf("a denial the recheck found is published after a kill: key %s", server.keyID())
			}
		})
	}
}

// foreignHookPublishTestBlock is a session start of process in session that
// found an unapproved project hook.
func foreignHookPublishTestBlock(session, process string) map[string]any {
	return map[string]any{"key": map[string]any{"connector": "claudecode", "session": session, "process": process}, "session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}}}
}

// foreignHookTestStoreRecord is the private session store record of one key
// part (enterprisepolicy sessionPathInDir).
func foreignHookTestStoreRecord(dataDir, identity, connectorName, kind, id string) string {
	digest := sha256.Sum256([]byte(connectorName + "\x00" + kind + "\x00" + id))
	return filepath.Join(enterprisepolicy.ForeignHookSessionStoreDir(dataDir, identity), kind+"-"+hex.EncodeToString(digest[:])[:40]+".json")
}

// Kill switch (round 2 and 3 scenarios): the exchange that records a block
// in the gateway's private store removes the record key first, under the
// account's lock. A gateway that stops after the store write and before it
// publishes the block (here: the publication is lost), or whose
// publication fails, leaves no allow the hook would honor during the
// outage: the earlier allow carries the removed key. An exchange that
// records no block removes nothing, and the gateway, back, denies from its
// store and publishes the block.
func TestForeignHookSessionGatewayKillsTheKeyBeforeItRecordsABlock(t *testing.T) {
	var writes []foreignHookPublished
	lost := false
	server := newForeignHookPublishTestServer(t, func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, _ time.Time) error {
		if lost {
			return errors.New("the gateway stopped")
		}
		writes = append(writes, foreignHookPublished{r, identity, key, decision.Deny, recordKey.ID()})
		return nil
	})
	kills := 0
	previousKill := foreignHookSessionKill
	blockedRecord := foreignHookTestStoreRecord(server.dataDir, server.alice, "claudecode", "s", "s-2")
	foreignHookSessionKill = func(r string) error {
		kills++
		if r != server.root {
			t.Errorf("killed the key of %s, want %s", r, server.root)
		}
		if _, err := os.Lstat(blockedRecord); kills == 1 && !errors.Is(err, fs.ErrNotExist) {
			t.Error("the block must not be in the private store before the key is removed")
		}
		return previousKill(r)
	}
	process := map[string]any{"connector": "claudecode", "session": "s-1", "process": "process-1"}
	if got := server.call(server.aliceToken, map[string]any{"key": process, "session_start": true, "decision": map[string]any{"deny": false}}); got.Deny {
		t.Fatalf("a clean session start is allowed: %+v", got)
	}
	allowedUnder := server.keyID()
	if kills != 0 || len(writes) != 1 || writes[0].deny || writes[0].keyID != allowedUnder {
		t.Fatalf("a clean exchange publishes its allow and removes nothing: %d %+v", kills, writes)
	}
	lost = true
	if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-2", "process-1")); !got.Deny {
		t.Fatalf("the session start that found the hook is blocked: %+v", got)
	}
	if kills != 1 || server.keyID() == allowedUnder || server.keyID() != "" {
		t.Fatalf("the key the earlier allow carries must be gone before the block (%d kills, key %q)", kills, server.keyID())
	}
	if _, err := os.Lstat(blockedRecord); err != nil {
		t.Fatalf("the block is in the private store: %v", err)
	}
	lost = false
	server.newKey()
	if got := server.call(server.aliceToken, map[string]any{"key": process, "decision": map[string]any{"deny": false}}); !got.Deny {
		t.Fatalf("the gateway, back, denies from its store: %+v", got)
	}
	if last := writes[len(writes)-1]; !last.deny || last.keyID != "" {
		t.Fatalf("the block is published after a kill: %+v", last)
	}
}

// Review P1 (round 3 scenario 1, kill switch): a gateway whose lookup of
// the record folder failed (on Windows, the protected ProgramData
// registration) used to deny the session start that found an unapproved
// hook before it recorded the block, and closed nothing: the agent
// process's earlier allow stayed usable, and once the lookup recovered the
// gateway allowed the process too. The gateway falls back to the folder it
// located last, or else to the one its data directory names, removes the
// key there before it records the block, and publishes the block there;
// the process stays blocked once the lookup recovers.
func TestForeignHookSessionGatewayRecordsABlockWhileItsLayoutLookupFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		located bool
	}{{"the folder it located last", true}, {"the folder its data directory names", false}} {
		t.Run(tc.name, func(t *testing.T) {
			var writes []foreignHookPublished
			server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
			var killed []string
			previousKill, previousDataDir := foreignHookSessionKill, foreignHookSessionRootForDataDir
			t.Cleanup(func() { foreignHookSessionRootForDataDir = previousDataDir })
			foreignHookSessionKill = func(r string) error {
				killed = append(killed, r)
				return previousKill(r)
			}
			foreignHookSessionRootForDataDir = func(dataDir string) (string, bool) {
				return server.root, !tc.located && dataDir == server.dataDir
			}
			process := runtime.GOOS + ":b:1:500"
			clean := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": process}, "decision": map[string]any{"deny": false}}
			if tc.located {
				if got := server.call(server.aliceToken, clean); got.Deny {
					t.Fatalf("a clean exchange is allowed: %+v", got)
				}
			}
			foreignHookSessionPublishRoot = func() (string, error) {
				return "", errors.New("the protected ProgramData registration cannot be read")
			}
			if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-2", process)); !got.Deny {
				t.Fatalf("the session start that found the hook is blocked: %+v", got)
			}
			if len(killed) != 1 || killed[0] != server.root || server.keyID() != "" {
				t.Fatalf("the key must be removed where the hook reads it: %v", killed)
			}
			if len(writes) == 0 || writes[len(writes)-1].root != server.root || !writes[len(writes)-1].deny {
				t.Fatalf("the block is published where the hook reads it: %+v", writes)
			}
			foreignHookSessionPublishRoot = func() (string, error) { return server.root, nil }
			if got := server.call(server.aliceToken, clean); !got.Deny {
				t.Fatalf("the agent process the block recorded stays blocked once the lookup recovers: %+v", got)
			}
		})
	}
}

// Kill switch (round 3 scenario 2): a key that cannot be removed (the
// volume refuses it) is logged, the block is still recorded, and it is
// published, which denies during an outage; the next denial tries the kill
// again. No denial is ever published before a kill was tried for it, and
// every one is published after a kill that took, or after one that took
// for the same process and session with no allow published for them since.
func TestForeignHookSessionGatewayPublishesNoDenialBeforeTheKill(t *testing.T) {
	var events []string
	server := newForeignHookPublishTestServer(t, func(_, _ string, _ enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, _ time.Time) error {
		events = append(events, map[bool]string{true: "deny", false: "allow"}[decision.Deny])
		return nil
	})
	var killErr error
	previousKill := foreignHookSessionKill
	foreignHookSessionKill = func(r string) error {
		if killErr != nil {
			events = append(events, "kill failed")
			return killErr
		}
		events = append(events, "kill")
		return previousKill(r)
	}
	process := runtime.GOOS + ":b:1:500"
	clean := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": process}, "decision": map[string]any{"deny": false}}
	killErr = errors.New("read-only file system")
	if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-2", process)); !got.Deny {
		t.Fatalf("a block is recorded when the key cannot be removed: %+v", got)
	}
	if got := server.call(server.aliceToken, clean); !got.Deny {
		t.Fatalf("the process stays blocked in the gateway: %+v", got)
	}
	killErr = nil
	if got := server.call(server.aliceToken, clean); !got.Deny {
		t.Fatalf("the process stays blocked: %+v", got)
	}
	// A blocked agent that keeps calling: the key is not removed again for
	// the same process and session.
	server.newKey()
	if got := server.call(server.aliceToken, clean); !got.Deny || server.keyID() == "" {
		t.Fatalf("a denial the gateway already removed the key for keeps the new key: %+v %q", got, server.keyID())
	}
	// Another account's allow, then a denial for a new session of the
	// blocked process: that session was never covered.
	other := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-3", "process": runtime.GOOS + ":b:1:600"}, "decision": map[string]any{"deny": false}}
	if got := server.call(server.bobToken, other); got.Deny {
		t.Fatalf("another account is allowed: %+v", got)
	}
	if got := server.call(server.aliceToken, map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-4", "process": process}, "decision": map[string]any{"deny": false}}); !got.Deny {
		t.Fatalf("a new session of the blocked process is denied: %+v", got)
	}
	want := []string{
		"kill failed", "kill failed", "deny", // the block: before it is recorded, then again before it is published
		"kill failed", "kill failed", "deny", // the block carried to the next call's session
		"kill", "deny", // the kill takes
		"deny",         // the same process and session: covered
		"allow",        // another account
		"kill", "deny", // the block carried to a new session of the blocked process
	}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("events %v, want %v", events, want)
	}
}

// The key removal cache forgets a process or session once an allow is
// published for it: a later denial removes the key again.
func TestForeignHookSessionKillCacheForgetsAnAllowedKey(t *testing.T) {
	var cache foreignHookSessionKillCache
	key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: "p-1"}
	if cache.covers("1001", key) {
		t.Fatal("an empty cache covers nothing")
	}
	cache.add("1001", key)
	if !cache.covers("1001", key) || cache.covers("1002", key) {
		t.Fatal("only the account's denial is covered")
	}
	if cache.covers("1001", enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-2", Process: "p-1"}) {
		t.Fatal("a new session of the process is not covered")
	}
	cache.forget("1001", enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-9", Process: "p-1"})
	if cache.covers("1001", key) {
		t.Fatal("an allow for the process must end the cover")
	}
	for i := 0; i <= foreignHookSessionKillCacheLimit; i++ {
		cache.add("1001", enterprisepolicy.SessionKey{Connector: "claudecode", Process: "p-" + time.Duration(i).String()})
	}
	if len(cache.entries) > foreignHookSessionKillCacheLimit {
		t.Fatalf("the cache must stay within its limit: %d", len(cache.entries))
	}
}
