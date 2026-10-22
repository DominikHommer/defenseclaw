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

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type foreignSessionResult struct {
	Deny   bool   `json:"deny"`
	Reason string `json:"reason"`
}

func writeTestForeignHookFence(t *testing.T, dir string, identities ...string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, identity := range identities {
		admission, active := enterprisepolicy.ForeignHookFencePaths(dir, identity)
		for _, path := range []string{admission, active} {
			if err := os.WriteFile(path, nil, 0o640); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// GAP-0457: an exchange queued behind an admitted removal must read the
// committed ledger. Reading first would let the old process keep an allow
// verdict while the guardian removes the hook it loaded.
func TestForeignHookExchangeReadsLedgerAfterRemovalAdmission(t *testing.T) {
	const identity = "1001"
	dir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, dir)
	writeTestForeignHookFence(t, dir, identity)
	previousTrust := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previousTrust })
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	writerUnlock, err := enterprisepolicy.LockForeignHookFence(t.Context(), dir, identity, true)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"key":           map[string]any{"connector": "claudecode", "session": "race", "process": "process"},
		"session_start": true, "decision": map[string]any{"deny": false},
	})
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", bytes.NewReader(body))
		ctx := withAuthenticatedHookConnector(req.Context(), "claudecode")
		ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
		response := httptest.NewRecorder()
		api.handleForeignHookSession(response, req.WithContext(ctx))
		result <- response
	}()
	select {
	case got := <-result:
		writerUnlock()
		t.Fatalf("exchange crossed the removal admission: %d %s", got.Code, got.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	pending := enterprisepolicy.ForeignHookRemoval{Identity: identity, Connector: "claudecode",
		Path: enterprisepolicy.ForeignHookCleanupPendingPath("test", "guardian"), At: time.Now().UTC().Format(time.RFC3339Nano), Mark: "unprovable"}
	ledger, err := enterprisepolicy.EncodeForeignHookRemovals(nil, []enterprisepolicy.ForeignHookRemoval{pending}, time.Now())
	if err != nil {
		writerUnlock()
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsFile), ledger, 0o640); err != nil {
		writerUnlock()
		t.Fatal(err)
	}
	writerUnlock()
	select {
	case got := <-result:
		var decision foreignSessionResult
		_ = json.Unmarshal(got.Body.Bytes(), &decision)
		if got.Code != http.StatusOK || !decision.Deny || !strings.Contains(decision.Reason, "cleanup and its denial record are not complete") {
			t.Fatalf("exchange missed admitted removal: %d %+v", got.Code, decision)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exchange did not resume after removal commit")
	}
}

func TestForeignHookExchangeWithoutRemovalFenceFailsClosed(t *testing.T) {
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, t.TempDir())
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	body := []byte(`{"key":{"connector":"claudecode","session":"s"},"session_start":true,"decision":{"deny":false}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", bytes.NewReader(body))
	ctx := withAuthenticatedHookConnector(req.Context(), "claudecode")
	ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, "1001")
	response := httptest.NewRecorder()
	api.handleForeignHookSession(response, req.WithContext(ctx))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("exchange without an admitted removal fence = %d %s", response.Code, response.Body.String())
	}
}

func TestForeignHookRemovalSourceSeesPendingLedgerWithUnchangedMetadata(t *testing.T) {
	dir := t.TempDir()
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
	const identity = "1001"
	pendingPath := enterprisepolicy.ForeignHookCleanupPendingPrefix + "0123456789abcdef>"
	oldPath := strings.Replace(pendingPath, "pending", "cleaner", 1)
	at := time.Now().UTC().Format(time.RFC3339)
	makeLedger := func(path string) []byte {
		t.Helper()
		data, err := enterprisepolicy.EncodeForeignHookRemovals(nil, []enterprisepolicy.ForeignHookRemoval{{
			Identity: identity, Connector: "cursor", Path: path, At: at, Mark: "linux:b:100",
		}}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	oldData, pendingData := makeLedger(oldPath), makeLedger(pendingPath)
	if len(oldData) != len(pendingData) {
		t.Fatalf("fixture ledger sizes differ: %d, %d", len(oldData), len(pendingData))
	}
	path := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsFile)
	if err := os.WriteFile(path, oldData, 0o600); err != nil {
		t.Fatal(err)
	}
	var source foreignHookRemovalSource
	if got, err := source.forIdentity(dir, identity); err != nil || len(got) != 1 || got[0].Path != oldPath {
		t.Fatalf("initial ledger: %+v (%v)", got, err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pendingData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("fixture metadata changed: before=%v after=%v err=%v", before, after, err)
	}
	if got, err := source.forIdentity(dir, identity); err != nil || len(got) != 1 || got[0].Path != pendingPath {
		t.Fatalf("pending denial hidden by unchanged file metadata: %+v (%v)", got, err)
	}
}

func TestForeignHookSessionGatewayPersistsAndBindsTheCaller(t *testing.T) {
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
	guardianDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	writeTestForeignHookFence(t, guardianDir, alice, bob)
	restoreValidate := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = restoreValidate })
	api, _, _ := newUserScopedTestServer(t, true, ledger, map[string]string{alice: "alice", bob: "bob"})
	handler := api.tokenAuth(api.managedHookSocketMux())
	aliceToken := userScopedTestToken(t, connector.UserScopedHookCredential, "claudecode", alice)
	bobToken := userScopedTestToken(t, connector.UserScopedHookCredential, "claudecode", bob)
	path := "/api/v1/foreign-hook-session/claudecode"
	// The loopback caller account each per-user credential belongs to.
	peerUIDs := map[string]int{aliceToken: 1001, bobToken: 1002}
	call := func(h http.Handler, token string, update map[string]any, claimedID string) (int, foreignSessionResult) {
		t.Helper()
		data, err := json.Marshal(update)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "foreign-hook-guard/1.0")
		req.Header.Set("Authorization", "Bearer "+token)
		if uid, ok := peerUIDs[token]; ok {
			req = req.WithContext(context.WithValue(req.Context(), acpConnPeerKey{}, &acpConnPeer{uid: uid, known: true}))
		}
		if claimedID != "" {
			req.Header.Set(llmEventUserIDHeader, claimedID)
		}
		response := httptest.NewRecorder()
		h.ServeHTTP(response, req)
		var decision foreignSessionResult
		_ = json.Unmarshal(response.Body.Bytes(), &decision)
		return response.Code, decision
	}
	blocked := map[string]any{
		"key":           map[string]any{"connector": "claudecode", "session": "s-1", "process": "process-1"},
		"session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}},
	}
	if status, result := call(handler, aliceToken, blocked, ""); status != http.StatusOK || !result.Deny {
		t.Fatalf("record blocked session: %d %+v", status, result)
	}
	clean := map[string]any{
		"key":           map[string]any{"connector": "claudecode", "session": "s-1", "process": "process-1"},
		"session_start": false,
		"decision":      map[string]any{"deny": false},
	}
	if status, result := call(handler, aliceToken, clean, bob); status != http.StatusForbidden || result.Deny {
		t.Fatalf("identity mismatch must be refused: %d %+v", status, result)
	}
	if status, result := call(handler, bobToken, clean, ""); status != http.StatusOK || result.Deny {
		t.Fatalf("another user must have separate state: %d %+v", status, result)
	}
	if status, _ := call(handler, "gateway-master-token", clean, ""); status != http.StatusForbidden {
		t.Fatalf("master token must not access the session route: %d", status)
	}
	// The guardian removed alice's Claude Code hook at clock 200 (and a Codex
	// one later): only her Claude Code processes started before then are
	// denied, naming the file. Bob's earlier Codex removals, however many and
	// however long the paths he chose (and one incomplete entry), never make
	// the ledger unreadable, which would deny everyone's calls.
	removed := "/home/alice/.claude/settings.json"
	earlier := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	flood := []enterprisepolicy.ForeignHookRemoval{{Identity: bob, Connector: "codex", At: earlier, Mark: runtime.GOOS + ":b:900"}}
	for i := 0; i < 2000; i++ {
		flood = append(flood, enterprisepolicy.ForeignHookRemoval{Identity: bob, Connector: "codex",
			Path: "/home/bob/" + strconv.Itoa(i) + strings.Repeat("<", 480), At: earlier, Mark: runtime.GOOS + ":b:900"})
	}
	data, err := enterprisepolicy.EncodeForeignHookRemovals(flood, []enterprisepolicy.ForeignHookRemoval{
		{Identity: alice, Connector: "claudecode", Path: removed, At: time.Now().UTC().Format(time.RFC3339), Mark: runtime.GOOS + ":b:200"},
		{Identity: alice, Connector: "codex", Path: "/home/alice/.codex/hooks.json", At: time.Now().UTC().Format(time.RFC3339), Mark: runtime.GOOS + ":b:900"},
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	withProcess := func(process string) map[string]any {
		return map[string]any{
			"key":           map[string]any{"connector": "claudecode", "session": "s-3", "process": process},
			"session_start": true,
			"decision":      map[string]any{"deny": false},
		}
	}
	if _, result := call(handler, aliceToken, withProcess(runtime.GOOS+":b:4242:100"), ""); !result.Deny || !strings.Contains(result.Reason, removed) || !strings.Contains(result.Reason, "restart the agent") {
		t.Fatalf("an agent process that started before the removal must be denied, naming the file: %+v", result)
	}
	if _, result := call(handler, aliceToken, withProcess(runtime.GOOS+":b:4343:300"), ""); result.Deny {
		t.Fatalf("an agent process that started after the removal (and before the other connector's) must be allowed: %+v", result)
	}
	if _, result := call(handler, bobToken, withProcess(runtime.GOOS+":b:4444:100"), ""); result.Deny {
		t.Fatalf("another account's agent must not be affected: %+v", result)
	}

	// The record survives a gateway process restart because it is stored in
	// the gateway data directory, not in an APIServer memory cache.
	restarted := NewAPIServer("", nil, nil, nil, nil, api.scannerCfg)
	restarted.userScopedCredentials = api.userScopedCredentials
	restartedHandler := restarted.tokenAuth(restarted.managedHookSocketMux())
	if status, result := call(restartedHandler, aliceToken, clean, ""); status != http.StatusOK || !result.Deny || !strings.Contains(result.Reason, "restart the agent") {
		t.Fatalf("gateway restart lost the block: %d %+v", status, result)
	}
}
