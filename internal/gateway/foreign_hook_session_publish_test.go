// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// foreignHookPublished is one protected record write of the gateway.
type foreignHookPublished struct {
	root, identity string
	key            enterprisepolicy.SessionKey
	deny           bool
	generation     string
}

// GAP-0352: every session exchange of a standalone gateway writes its answer
// into the caller's protected session record, for the verified caller only,
// stamped with the record folder's current generation: a block for the
// session start that found an unapproved hook, the block it then enforces,
// and the allow of another account.
func TestForeignHookSessionGatewayPublishesTheProtectedRecord(t *testing.T) {
	var writes []foreignHookPublished
	root := t.TempDir()
	server := newForeignHookPublishTestServer(t, root, func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, generation string, _ time.Time) error {
		writes = append(writes, foreignHookPublished{r, identity, key, decision.Deny, generation})
		return nil
	})
	generation := server.generation()
	if generation == "" {
		t.Fatal("the test record folder has no generation")
	}
	alice, bob := server.alice, server.bob
	key := map[string]any{"connector": "claudecode", "session": "s-1", "process": "process-1"}
	server.call(server.aliceToken, map[string]any{"key": key, "session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}}})
	server.call(server.aliceToken, map[string]any{"key": key, "decision": map[string]any{"deny": false}})
	server.call(server.bobToken, map[string]any{"key": key, "decision": map[string]any{"deny": false}})
	sessionKey := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: "process-1"}
	want := []foreignHookPublished{
		{root, alice, sessionKey, true, generation},
		{root, alice, sessionKey, true, generation},
		{root, bob, sessionKey, false, generation},
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

// Lead directive (GAP-0352 review loop round 1): the gateway reads the
// record generation before the guardian's removals, and the guardian bumps
// it after it recorded a removal, so no interleaving leaves an allow that a
// removal should have ended:
//   - the guardian records and bumps after the gateway read the ledger,
//     before the exchange answers: the allow it published first (from the
//     earlier ledger) carries the generation the bump ended, so the hook
//     refuses it, and the exchange reads the removals again before it
//     answers, so this call is denied too and the denial is published with
//     the current generation (1.0.4 review loop round 4: the call was
//     allowed and only the next one denied);
//   - the guardian records and bumps after the gateway read the generation,
//     before the ledger: the exchange reads the new ledger and is denied;
//   - the guardian rewrites the ledger in place, keeping its file, time and
//     size, and bumps: the cached ledger is read again because the
//     generation changed.
func TestForeignHookSessionGatewayStampsTheGenerationItReadBeforeTheRemovals(t *testing.T) {
	var writes []foreignHookPublished
	var afterRead func()
	root := t.TempDir()
	server := newForeignHookPublishTestServer(t, root, func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, generation string, _ time.Time) error {
		writes = append(writes, foreignHookPublished{r, identity, key, decision.Deny, generation})
		return nil
	})
	early := runtime.GOOS + ":b:1:100"
	ledgerPath := filepath.Join(server.guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	encode := func(identity, file string) []byte {
		t.Helper()
		now := time.Now().UTC()
		data, _, err := enterprisepolicy.EncodeForeignHookRemovals(nil, []enterprisepolicy.ForeignHookRemoval{{
			Identity: identity, Connector: "claudecode", Path: file, At: now.Format(time.RFC3339), Mark: runtime.GOOS + ":b:200",
		}}, now)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	guardian := func(identity, file string) {
		t.Helper()
		if err := os.WriteFile(ledgerPath+".tmp", encode(identity, file), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(ledgerPath+".tmp", ledgerPath); err != nil {
			t.Fatal(err)
		}
		server.bump()
	}
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
	foreignHookSessionPublish = func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, generation string, now time.Time) error {
		if afterRead != nil {
			afterRead()
			afterRead = nil
		}
		return previous(r, identity, key, decision, generation, now)
	}
	t.Cleanup(func() { foreignHookSessionPublish = previous })
	afterRead = func() { guardian(server.alice, "/home/alice/.claude/settings.json") }
	before := server.generation()
	if got := server.call(server.aliceToken, allow); !got.Deny || !strings.Contains(got.Reason, "started before DefenseClaw removed") {
		t.Fatalf("an exchange whose removal the guardian recorded before it answered must be denied: %+v", got)
	}
	if len(writes) < 2 {
		t.Fatalf("the allow and the denial that replaces it must both be published: %+v", writes)
	}
	if published := writes[len(writes)-2]; published.deny || published.generation != before || published.generation == server.generation() {
		t.Fatalf("its first allow must carry the generation the bump ended (%s, now %s): %+v", before, server.generation(), published)
	}
	if published := last(); !published.deny || published.generation != server.generation() {
		t.Fatalf("the denial that replaces it carries the current generation: %+v", published)
	}
	if got := server.call(server.aliceToken, allow); !got.Deny || !strings.Contains(got.Reason, "started before DefenseClaw removed") {
		t.Fatalf("the next exchange must be denied: %+v", got)
	}
	if published := last(); !published.deny || published.generation != server.generation() {
		t.Fatalf("the denial carries the current generation: %+v", published)
	}

	// After the generation read, before the ledger read.
	if err := os.Remove(ledgerPath); err != nil {
		t.Fatal(err)
	}
	server.bump()
	if got := server.call(server.aliceToken, allow); got.Deny {
		t.Fatalf("no ledger allows: %+v", got)
	}
	previousGeneration := foreignHookSessionGeneration
	foreignHookSessionGeneration = func(r string) (string, error) {
		generation, err := previousGeneration(r)
		foreignHookSessionGeneration = previousGeneration
		guardian(server.alice, "/home/alice/.claude/settings.json")
		return generation, err
	}
	t.Cleanup(func() { foreignHookSessionGeneration = previousGeneration })
	if got := server.call(server.aliceToken, allow); !got.Deny {
		t.Fatalf("an exchange that read the generation before the guardian's bump reads the new ledger and is denied: %+v", got)
	}

	// The cached ledger follows the generation, whatever the file says.
	other := encode(server.bob, "/home/x/.claude/settings.json")
	mine := encode(server.alice, "/home/x/.claude/settings.json")
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
	server.bump()
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
	server.bump()
	if got := server.call(server.aliceToken, allow); !got.Deny {
		t.Fatalf("a ledger rewritten in place before a bump must be read again: %+v", got)
	}
}

// foreignHookPublishTestServer is a standalone user-scoped gateway with two
// enrolled accounts whose protected-record writes go to publish. Its record
// folder has a generation file the test account owns.
type foreignHookPublishTestServer struct {
	alice, bob           string
	aliceToken, bobToken string
	guardianDir          string
	dataDir              string
	root                 string
	call                 func(token string, update map[string]any) enterprisepolicy.GuardDecision
	t                    *testing.T
}

// generation is the record folder's current generation.
func (s *foreignHookPublishTestServer) generation() string {
	s.t.Helper()
	generation, err := foreignHookSessionGeneration(s.root)
	if err != nil {
		return ""
	}
	return generation
}

// bump bumps the record generation, as the guardian does after a removal.
func (s *foreignHookPublishTestServer) bump() {
	s.t.Helper()
	if err := enterprisepolicy.BumpPublishedSessionGeneration(s.root); err != nil {
		s.t.Fatal(err)
	}
}

// foreignHookTestGeneration reads the generation the way
// enterprisepolicy.PublishedSessionGeneration does, for a generation file
// the test account owns (the gateway accepts only root's or SYSTEM's).
func foreignHookTestGeneration(root string) (string, error) {
	path, ok := enterprisepolicy.PublishedSessionGenerationPath(root)
	if !ok {
		return "", errors.New("no generation path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	return strconv.FormatInt(info.ModTime().UnixNano(), 10), nil
}

func newForeignHookPublishTestServer(t *testing.T, root string, publish func(string, string, enterprisepolicy.SessionKey, enterprisepolicy.GuardDecision, string, time.Time) error) *foreignHookPublishTestServer {
	t.Helper()
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
	previousRoot, previousPublish, previousGeneration := foreignHookSessionPublishRoot, foreignHookSessionPublish, foreignHookSessionGeneration
	foreignHookSessionPublishRoot = func() (string, error) { return root, nil }
	foreignHookSessionPublish = publish
	foreignHookSessionGeneration = foreignHookTestGeneration
	t.Cleanup(func() {
		validateManagedGuardianAuthorization = restoreValidate
		foreignHookSessionPublishRoot, foreignHookSessionPublish, foreignHookSessionGeneration = previousRoot, previousPublish, previousGeneration
	})
	server.bump()
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
// an account closed because it could not record a removal or bump the
// record generation, every guarded call of the account is denied and only
// blocks are published; another account is not affected, and the account
// is allowed again once the mark is cleared. The mark is on the account's
// private session store, so an account that deletes or moves its folder of
// protected records, or empties the record root, does not clear it.
func TestForeignHookSessionGatewayDeniesAnAccountWhoseRemovalIsPending(t *testing.T) {
	var publishes []string
	root := t.TempDir()
	server := newForeignHookPublishTestServer(t, root, func(_, identity string, _ enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, _ string, _ time.Time) error {
		publishes = append(publishes, identity+" deny="+strconv.FormatBool(decision.Deny))
		return nil
	})
	accountDir, _ := enterprisepolicy.PublishedSessionIdentityDir(root, server.alice)
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
	if got := server.call(server.bobToken, allow); got.Deny {
		t.Fatalf("another account must be allowed: %+v", got)
	}
	if err := enterprisepolicy.ClearForeignHookRemovalPending(server.dataDir, server.alice); err != nil {
		t.Fatal(err)
	}
	if got := server.call(server.aliceToken, allow); got.Deny {
		t.Fatalf("the account must be allowed once the mark is cleared: %+v", got)
	}
	want := []string{server.alice + " deny=true", server.alice + " deny=true", server.bob + " deny=false", server.alice + " deny=false"}
	if strings.Join(publishes, ",") != strings.Join(want, ",") {
		t.Fatalf("published %v, want %v", publishes, want)
	}
}

// Review P2 (GAP-0352, loop round 3): a standalone gateway that cannot
// locate its protected session record folder (on Windows, the protected
// ProgramData registration) denies the exchange: it cannot publish its
// answer. Nothing is published, the account's pending mark keeps its own
// reason, and the exchange is allowed again once the folder is found. A
// record folder whose generation cannot be read is published to without a
// generation, so the allow proves nothing during an outage.
func TestForeignHookSessionGatewayDeniesWhenTheRecordFolderCannotBeLocated(t *testing.T) {
	var writes []foreignHookPublished
	root := t.TempDir()
	server := newForeignHookPublishTestServer(t, root, func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, generation string, _ time.Time) error {
		writes = append(writes, foreignHookPublished{r, identity, key, decision.Deny, generation})
		return nil
	})
	lookupErr := errors.New("the protected ProgramData registration cannot be read")
	foreignHookSessionPublishRoot = func() (string, error) {
		if lookupErr != nil {
			return "", lookupErr
		}
		return root, nil
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
	if got := server.call(server.aliceToken, allow); got.Deny || len(writes) != 1 || writes[0].generation != server.generation() {
		t.Fatalf("once the folder is found the exchange is allowed and published with the generation: %+v %+v", got, writes)
	}
	foreignHookSessionGeneration = func(string) (string, error) { return "", errors.New("the generation file is not root's") }
	if got := server.call(server.aliceToken, allow); got.Deny || len(writes) != 2 || writes[1].generation != "" {
		t.Fatalf("without a generation the allow is published without one: %+v %+v", got, writes)
	}
}

// Review P2 (GAP-0352, 1.0.4 loop round 4): the guardian records a removal
// after an exchange read the removals and before it answers. The exchange
// reads the generation and the removals again before it answers, so every
// way the guardian records one denies this call, and the denial is the
// record the hook finds: a ledger write followed by its bump, a pending
// mark (a ledger write or a bump that failed), and a ledger write the
// guardian has not bumped yet. A removal for another account, or a bump
// alone, keeps the allow, published again with the new generation. With
// nothing recorded, or a denial from the scan, the exchange publishes once.
func TestForeignHookSessionGatewayRechecksTheRemovalsBeforeItAnswers(t *testing.T) {
	process := runtime.GOOS + ":b:1:100"
	allow := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": process}, "decision": map[string]any{"deny": false}}
	deny := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-2", "process": process},
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: unverifiable hook"}}
	for _, c := range []struct {
		name     string
		guardian func(s *foreignHookPublishTestServer, ledger func(identity string))
		update   map[string]any
		deny     string // the reason the answer must carry, "" for an allow
		writes   int
	}{
		{name: "ledger and bump", guardian: func(s *foreignHookPublishTestServer, ledger func(string)) { ledger(s.alice); s.bump() }, update: allow, deny: "started before DefenseClaw removed", writes: 2},
		{name: "pending mark and bump", guardian: func(s *foreignHookPublishTestServer, _ func(string)) {
			if err := enterprisepolicy.MarkForeignHookRemovalPending(s.dataDir, s.alice); err != nil {
				s.t.Fatal(err)
			}
			s.bump()
		}, update: allow, deny: "could not record the removal yet", writes: 2},
		{name: "pending mark, bump failed", guardian: func(s *foreignHookPublishTestServer, _ func(string)) {
			if err := enterprisepolicy.MarkForeignHookRemovalPending(s.dataDir, s.alice); err != nil {
				s.t.Fatal(err)
			}
		}, update: allow, deny: "could not record the removal yet", writes: 2},
		{name: "ledger not bumped yet", guardian: func(s *foreignHookPublishTestServer, ledger func(string)) { ledger(s.alice) }, update: allow, deny: "started before DefenseClaw removed", writes: 2},
		{name: "another account's removal", guardian: func(s *foreignHookPublishTestServer, ledger func(string)) { ledger(s.bob); s.bump() }, update: allow, writes: 2},
		{name: "bump alone", guardian: func(s *foreignHookPublishTestServer, _ func(string)) { s.bump() }, update: allow, writes: 2},
		{name: "nothing recorded", guardian: func(*foreignHookPublishTestServer, func(string)) {}, update: allow, writes: 1},
		{name: "a denial from the scan", guardian: func(s *foreignHookPublishTestServer, ledger func(string)) { ledger(s.alice); s.bump() }, update: deny, deny: "unverifiable hook", writes: 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			var writes []foreignHookPublished
			root := t.TempDir()
			var server *foreignHookPublishTestServer
			ran := false
			server = newForeignHookPublishTestServer(t, root, func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, generation string, _ time.Time) error {
				writes = append(writes, foreignHookPublished{r, identity, key, decision.Deny, generation})
				if !ran {
					// The guardian runs after the exchange decided, before
					// it answers.
					ran = true
					c.guardian(server, func(identity string) {
						now := time.Now().UTC()
						data, _, err := enterprisepolicy.EncodeForeignHookRemovals(nil, []enterprisepolicy.ForeignHookRemoval{{
							Identity: identity, Connector: "claudecode", Path: "/home/x/.claude/settings.json", At: now.Format(time.RFC3339), Mark: runtime.GOOS + ":b:200",
						}}, now)
						if err != nil {
							t.Fatal(err)
						}
						ledgerPath := filepath.Join(server.guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
						if err := os.WriteFile(ledgerPath+".tmp", data, 0o640); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(ledgerPath+".tmp", ledgerPath); err != nil {
							t.Fatal(err)
						}
					})
				}
				return nil
			})
			before := server.generation()
			got := server.call(server.aliceToken, c.update)
			if c.deny == "" && got.Deny || c.deny != "" && (!got.Deny || !strings.Contains(got.Reason, c.deny)) {
				t.Fatalf("answer %+v, want deny reason %q", got, c.deny)
			}
			if len(writes) != c.writes {
				t.Fatalf("published %+v, want %d writes", writes, c.writes)
			}
			if writes[0].generation != before || writes[0].deny != (c.update["decision"].(map[string]any)["deny"] == true) {
				t.Fatalf("the first record is the exchange's own answer, with the generation it read first: %+v (generation %s)", writes[0], before)
			}
			if final := writes[len(writes)-1]; final.deny != got.Deny || len(writes) > 1 && final.generation != server.generation() {
				t.Fatalf("the last record is the answer, with the current generation %s: %+v", server.generation(), final)
			}
		})
	}
}
