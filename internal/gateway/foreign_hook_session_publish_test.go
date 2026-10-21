// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0352: every session exchange of a standalone gateway writes its answer
// into the caller's protected session record, for the verified caller only:
// a block for the session start that found an unapproved hook, the block it
// then enforces, and the allow of another account.
func TestForeignHookSessionGatewayPublishesTheProtectedRecord(t *testing.T) {
	type published struct {
		root, identity string
		key            enterprisepolicy.SessionKey
		deny           bool
	}
	var writes []published
	root := t.TempDir()
	server := newForeignHookPublishTestServer(t, root, func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, _ time.Time) error {
		writes = append(writes, published{r, identity, key, decision.Deny})
		return nil
	})
	alice, bob := server.alice, server.bob
	key := map[string]any{"connector": "claudecode", "session": "s-1", "process": "process-1"}
	server.call(server.aliceToken, map[string]any{"key": key, "session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}}})
	server.call(server.aliceToken, map[string]any{"key": key, "decision": map[string]any{"deny": false}})
	server.call(server.bobToken, map[string]any{"key": key, "decision": map[string]any{"deny": false}})
	want := []published{
		{root, alice, enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: "process-1"}, true},
		{root, alice, enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: "process-1"}, true},
		{root, bob, enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: "process-1"}, false},
	}
	if len(writes) != len(want) {
		t.Fatalf("published %+v, want %+v", writes, want)
	}
	for i := range want {
		if writes[i] != want[i] {
			t.Fatalf("publish %d = %+v, want %+v", i, writes[i], want[i])
		}
	}
	if len(server.withdrawn) != 0 {
		t.Fatalf("an unchanged removal ledger must withdraw nothing: %v", server.withdrawn)
	}
}

// Review P2 (GAP-0352): the gateway reads the guardian's removal ledger
// before it takes the per-identity lock, and the guardian revokes the
// account's records after it wrote the ledger. An allow answered from the
// ledger the guardian replaced, created or removed while the exchange ran
// is withdrawn after its publication, so it never outlives the guardian's
// revocation into an outage; a block, or an allow whose ledger did not
// change, stays.
func TestForeignHookSessionGatewayWithdrawsAnAllowWhoseRemovalLedgerChanged(t *testing.T) {
	var guardian func()
	var publishes []string
	server := newForeignHookPublishTestServer(t, t.TempDir(), func(_, identity string, _ enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, _ time.Time) error {
		publishes = append(publishes, identity+" deny="+strconv.FormatBool(decision.Deny))
		if guardian != nil {
			// The guardian runs between the gateway's ledger read and
			// this publication.
			guardian()
			guardian = nil
		}
		return nil
	})
	ledgerPath := filepath.Join(server.guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	writeLedger := func(path string) {
		t.Helper()
		now := time.Now().UTC()
		data, err := enterprisepolicy.EncodeForeignHookRemovals(nil, []enterprisepolicy.ForeignHookRemoval{{
			Identity: server.bob, Connector: "claudecode", Path: path, At: now.Format(time.RFC3339), Mark: agentprocess.Now(),
		}}, now)
		if err != nil {
			t.Fatal(err)
		}
		tmp := ledgerPath + ".tmp"
		if err := os.WriteFile(tmp, data, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, ledgerPath); err != nil {
			t.Fatal(err)
		}
	}
	allow := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": "process-1"}, "decision": map[string]any{"deny": false}}
	step := func(name string, token string, update map[string]any, during func(), wantWithdrawn int) {
		t.Helper()
		guardian = during
		server.call(token, update)
		if len(server.withdrawn) != wantWithdrawn {
			t.Fatalf("%s: withdrawn %v, want %d withdrawals (published %v)", name, server.withdrawn, wantWithdrawn, publishes)
		}
	}
	step("no ledger", server.aliceToken, allow, nil, 0)
	step("the guardian writes the first ledger", server.aliceToken, allow, func() { writeLedger("/home/bob/.claude/settings.json") }, 1)
	if !strings.HasPrefix(server.withdrawn[0], server.alice+" ") {
		t.Fatalf("the withdrawal must name the caller's key: %v", server.withdrawn)
	}
	step("an unchanged ledger", server.aliceToken, allow, nil, 1)
	step("the guardian replaces the ledger", server.aliceToken, allow, func() { writeLedger("/home/bob/.github/hooks/x.json") }, 2)
	deny := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-2", "process": "process-2"}, "session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}}}
	step("a block during a ledger change", server.aliceToken, deny, func() { writeLedger("/home/bob/.codex/hooks.json") }, 2)
	step("the guardian removes the ledger", server.aliceToken, allow, func() {
		if err := os.Remove(ledgerPath); err != nil {
			t.Fatal(err)
		}
	}, 3)
	step("still no ledger", server.aliceToken, allow, nil, 3)
}

// Review P2 (GAP-0352): a removal the guardian could not write to its
// ledger is held next to the account's protected records. The gateway
// denies with it as with the ledger, so the next exchange of an agent
// process that started before the removal publishes a block, not the allow
// the guardian revoked. A process that started after it is allowed, another
// account is not affected, a hold that does not parse denies, and an allow
// answered while the guardian wrote or removed the hold is withdrawn.
func TestForeignHookSessionGatewayDeniesWithTheGuardiansHeldRemovals(t *testing.T) {
	type published struct {
		identity, process string
		deny              bool
	}
	var writes []published
	var guardian func()
	root := t.TempDir()
	server := newForeignHookPublishTestServer(t, root, func(_, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, _ time.Time) error {
		writes = append(writes, published{identity, key.Process, decision.Deny})
		if guardian != nil {
			guardian()
			guardian = nil
		}
		return nil
	})
	early, late := runtime.GOOS+":b:1:100", runtime.GOOS+":b:1:300"
	holdPath, ok := enterprisepolicy.ForeignHookRemovalHoldPath(root, server.alice)
	if !ok {
		t.Fatal("no hold path")
	}
	writeHold := func() {
		t.Helper()
		now := time.Now().UTC()
		data, err := enterprisepolicy.EncodeForeignHookRemovals(nil, []enterprisepolicy.ForeignHookRemoval{{
			Identity: server.alice, Connector: "claudecode", Path: "/home/alice/.claude/settings.json",
			At: now.Format(time.RFC3339), Mark: runtime.GOOS + ":b:200",
		}}, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(holdPath+".tmp", data, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(holdPath+".tmp", holdPath); err != nil {
			t.Fatal(err)
		}
	}
	allow := func(process string) map[string]any {
		return map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": process}, "decision": map[string]any{"deny": false}}
	}
	expect := func(name string, want []published, withdrawn int) {
		t.Helper()
		if len(writes) != len(want) {
			t.Fatalf("%s: published %+v, want %+v", name, writes, want)
		}
		for i := range want {
			if writes[i] != want[i] {
				t.Fatalf("%s: publish %d = %+v, want %+v", name, i, writes[i], want[i])
			}
		}
		if len(server.withdrawn) != withdrawn {
			t.Fatalf("%s: withdrawn %v, want %d", name, server.withdrawn, withdrawn)
		}
		writes = nil
	}
	writeHold()
	server.call(server.aliceToken, allow(early))
	server.call(server.aliceToken, allow(late))
	server.call(server.bobToken, allow(early))
	expect("held removal", []published{{server.alice, early, true}, {server.alice, late, false}, {server.bob, early, false}}, 0)

	if err := os.WriteFile(holdPath, []byte(`{"version":1`), 0o640); err != nil {
		t.Fatal(err)
	}
	server.call(server.aliceToken, allow(late))
	expect("a hold that does not parse", []published{{server.alice, late, true}}, 0)

	if err := os.Remove(holdPath); err != nil {
		t.Fatal(err)
	}
	guardian = writeHold
	server.call(server.aliceToken, allow(late))
	expect("the guardian writes the hold", []published{{server.alice, late, false}, {server.alice, late, false}}, 1)
	guardian = func() { _ = os.Remove(holdPath) }
	server.call(server.aliceToken, allow(late))
	expect("the guardian removes the hold", []published{{server.alice, late, false}, {server.alice, late, false}}, 2)
	server.call(server.aliceToken, allow(late))
	expect("no hold", []published{{server.alice, late, false}}, 2)
}

// foreignHookPublishTestServer is a standalone user-scoped gateway with two
// enrolled accounts whose protected-record writes go to publish.
type foreignHookPublishTestServer struct {
	alice, bob           string
	aliceToken, bobToken string
	guardianDir          string
	withdrawn            []string
	call                 func(token string, update map[string]any) enterprisepolicy.GuardDecision
}

func newForeignHookPublishTestServer(t *testing.T, root string, publish func(string, string, enterprisepolicy.SessionKey, enterprisepolicy.GuardDecision, time.Time) error) *foreignHookPublishTestServer {
	t.Helper()
	server := &foreignHookPublishTestServer{}
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
	previousRoot, previousPublish, previousWithdraw := foreignHookSessionPublishRoot, foreignHookSessionPublish, foreignHookSessionWithdraw
	foreignHookSessionPublishRoot = func() (string, error) { return root, nil }
	foreignHookSessionPublish = publish
	foreignHookSessionWithdraw = func(r, identity string, key enterprisepolicy.SessionKey) error {
		if r != root {
			t.Errorf("withdrawn under %s, want %s", r, root)
		}
		server.withdrawn = append(server.withdrawn, identity+" "+key.Connector+" "+key.Session+" "+key.Process)
		return nil
	}
	t.Cleanup(func() {
		validateManagedGuardianAuthorization = restoreValidate
		foreignHookSessionPublishRoot, foreignHookSessionPublish, foreignHookSessionWithdraw = previousRoot, previousPublish, previousWithdraw
	})
	api, _, _ := newUserScopedTestServer(t, true, ledger, map[string]string{alice: "alice", bob: "bob"})
	if api.scannerCfg == nil || !api.scannerCfg.StandaloneEnterprise() {
		t.Skip("the user-scoped test server is not a standalone deployment")
	}
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

// Review P2 (GAP-0352, loop round 2): the answer the hook gets, not only
// the protected record, follows a removal the guardian recorded while the
// exchange ran. An allow read from the earlier ledger, hold or mark is
// decided again from the new state: a removal of this account's connector
// after the agent process started denies it, and so does the account's
// pending mark; a removal for another account leaves the allow. When the
// removals keep changing, the call is denied.
func TestForeignHookSessionGatewayAnswerFollowsARemovalRecordedDuringTheExchange(t *testing.T) {
	var during func()
	runs := 0
	var publishes []bool
	root := t.TempDir()
	server := newForeignHookPublishTestServer(t, root, func(_, _ string, _ enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, _ time.Time) error {
		publishes = append(publishes, decision.Deny)
		if during != nil && runs > 0 {
			runs--
			during()
		}
		return nil
	})
	early := runtime.GOOS + ":b:1:100"
	ledgerPath := filepath.Join(server.guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	holdPath, _ := enterprisepolicy.ForeignHookRemovalHoldPath(root, server.alice)
	replace := func(path, identity, file string) {
		t.Helper()
		now := time.Now().UTC()
		data, err := enterprisepolicy.EncodeForeignHookRemovals(nil, []enterprisepolicy.ForeignHookRemoval{{
			Identity: identity, Connector: "claudecode", Path: file, At: now.Format(time.RFC3339), Mark: runtime.GOOS + ":b:200",
		}}, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".tmp", data, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			t.Fatal(err)
		}
	}
	accountDir, _ := enterprisepolicy.PublishedSessionIdentityDir(root, server.alice)
	allow := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": early}, "decision": map[string]any{"deny": false}}
	files := 0
	for _, tc := range []struct {
		name      string
		guardian  func()
		times     int
		reason    string
		publishes []bool
	}{
		{"a ledger removal for another account", func() { replace(ledgerPath, server.bob, "/home/bob/.claude/settings.json") }, 1, "", []bool{false, false}},
		{"a ledger removal for this account", func() { replace(ledgerPath, server.alice, "/home/alice/.claude/settings.json") }, 1, "started before DefenseClaw removed", []bool{false, true}},
		{"a held removal for this account", func() { replace(holdPath, server.alice, "/home/alice/.claude/settings.json") }, 1, "started before DefenseClaw removed", []bool{false, true}},
		{"the account's pending mark", func() {
			if err := os.MkdirAll(accountDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := enterprisepolicy.MarkForeignHookRemovalPending(root, server.alice); err != nil {
				t.Fatal(err)
			}
		}, 1, "could not record the removal yet", []bool{false, true}},
		{"removals that keep changing", func() {
			files++
			replace(ledgerPath, server.bob, "/home/bob/.claude/"+strconv.Itoa(files)+".json")
		}, 10, "cannot verify", []bool{false, false, false, true}},
	} {
		for _, path := range []string{ledgerPath, holdPath} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
		if err := enterprisepolicy.ClearForeignHookRemovalPending(root, server.alice); err != nil {
			t.Fatal(err)
		}
		server.call(server.aliceToken, allow)
		publishes = nil
		during, runs = tc.guardian, tc.times
		got := server.call(server.aliceToken, allow)
		during = nil
		if tc.reason == "" && got.Deny || tc.reason != "" && (!got.Deny || !strings.Contains(got.Reason, tc.reason)) {
			t.Fatalf("%s: answer %+v, want reason %q", tc.name, got, tc.reason)
		}
		if len(publishes) != len(tc.publishes) {
			t.Fatalf("%s: published %v, want %v", tc.name, publishes, tc.publishes)
		}
		for i := range publishes {
			if publishes[i] != tc.publishes[i] {
				t.Fatalf("%s: published %v, want %v", tc.name, publishes, tc.publishes)
			}
		}
	}
}

// Review P2 (GAP-0352, loop round 2): while the guardian holds an account
// closed because it could not record a removal, every guarded call of the
// account is denied and only blocks are published; another account is not
// affected, and the account is allowed again once the mark is cleared.
func TestForeignHookSessionGatewayDeniesAnAccountWhoseRemovalIsPending(t *testing.T) {
	var publishes []string
	root := t.TempDir()
	server := newForeignHookPublishTestServer(t, root, func(_, identity string, _ enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, _ time.Time) error {
		publishes = append(publishes, identity+" deny="+strconv.FormatBool(decision.Deny))
		return nil
	})
	accountDir, _ := enterprisepolicy.PublishedSessionIdentityDir(root, server.alice)
	if err := os.MkdirAll(accountDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := enterprisepolicy.MarkForeignHookRemovalPending(root, server.alice); err != nil {
		t.Fatal(err)
	}
	allow := map[string]any{"key": map[string]any{"connector": "claudecode", "session": "s-1", "process": runtime.GOOS + ":b:1:500"}, "decision": map[string]any{"deny": false}}
	if got := server.call(server.aliceToken, allow); !got.Deny || !strings.Contains(got.Reason, "could not record the removal yet") {
		t.Fatalf("a held account must be denied: %+v", got)
	}
	if got := server.call(server.bobToken, allow); got.Deny {
		t.Fatalf("another account must be allowed: %+v", got)
	}
	if err := enterprisepolicy.ClearForeignHookRemovalPending(root, server.alice); err != nil {
		t.Fatal(err)
	}
	if got := server.call(server.aliceToken, allow); got.Deny {
		t.Fatalf("the account must be allowed once the mark is cleared: %+v", got)
	}
	want := []string{server.alice + " deny=true", server.bob + " deny=false", server.alice + " deny=false"}
	if strings.Join(publishes, ",") != strings.Join(want, ",") || len(server.withdrawn) != 0 {
		t.Fatalf("published %v (withdrawn %v), want %v", publishes, server.withdrawn, want)
	}
}
