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

// foreignHookPublishTestServer is a standalone user-scoped gateway with two
// enrolled accounts whose protected-record writes go to publish.
type foreignHookPublishTestServer struct {
	alice, bob           string
	aliceToken, bobToken string
	guardianDir          string
	withdrawn            []string
	call                 func(token string, update map[string]any)
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
	server.call = func(token string, update map[string]any) {
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
	}
	return server
}
