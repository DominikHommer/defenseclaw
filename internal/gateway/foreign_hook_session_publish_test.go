// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0352: every session exchange of a standalone gateway writes its answer
// into the caller's protected session record, for the verified caller only:
// a block for the session start that found an unapproved hook, the block it
// then enforces, and the allow of another account.
func TestForeignHookSessionGatewayPublishesTheProtectedRecord(t *testing.T) {
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
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, t.TempDir())
	restoreValidate := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	type published struct {
		root, identity string
		key            enterprisepolicy.SessionKey
		deny           bool
	}
	var writes []published
	root := t.TempDir()
	previousRoot, previousPublish := foreignHookSessionPublishRoot, foreignHookSessionPublish
	foreignHookSessionPublishRoot = func() (string, error) { return root, nil }
	foreignHookSessionPublish = func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, _ time.Time) error {
		writes = append(writes, published{r, identity, key, decision.Deny})
		return nil
	}
	t.Cleanup(func() {
		validateManagedGuardianAuthorization = restoreValidate
		foreignHookSessionPublishRoot, foreignHookSessionPublish = previousRoot, previousPublish
	})
	api, _, _ := newUserScopedTestServer(t, true, ledger, map[string]string{alice: "alice", bob: "bob"})
	if api.scannerCfg == nil || !api.scannerCfg.StandaloneEnterprise() {
		t.Skip("the user-scoped test server is not a standalone deployment")
	}
	handler := api.tokenAuth(api.managedHookSocketMux())
	aliceToken := userScopedTestToken(t, connector.UserScopedHookCredential, "claudecode", alice)
	bobToken := userScopedTestToken(t, connector.UserScopedHookCredential, "claudecode", bob)
	peerUIDs := map[string]int{aliceToken: 1001, bobToken: 1002}
	call := func(token string, update map[string]any) {
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
	key := map[string]any{"connector": "claudecode", "session": "s-1", "process": "process-1"}
	call(aliceToken, map[string]any{"key": key, "session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}}})
	call(aliceToken, map[string]any{"key": key, "decision": map[string]any{"deny": false}})
	call(bobToken, map[string]any{"key": key, "decision": map[string]any{"deny": false}})
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
}
