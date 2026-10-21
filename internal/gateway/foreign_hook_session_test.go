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
	if err := os.WriteFile(filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFenceFile), nil, 0o640); err != nil {
		t.Fatal(err)
	}
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

type pausedForeignHookResponse struct {
	http.ResponseWriter
	entered chan struct{}
	resume  chan struct{}
}

func (w pausedForeignHookResponse) Write(data []byte) (int, error) {
	close(w.entered)
	<-w.resume
	return w.ResponseWriter.Write(data)
}

// GAP-0348: an allow's response write and a guardian removal commit must
// have one order across processes. The permanent fence cannot be replaced
// when the ledger is atomically replaced.
func TestForeignHookSessionAllowResponseFencesRemovalCommit(t *testing.T) {
	guardianDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
	fence := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFenceFile)
	if err := os.WriteFile(fence, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	identity := "1001"
	if runtime.GOOS == "windows" {
		identity = "S-1-5-21-1111-2222-3333-1001"
	}
	body := []byte(`{"key":{"connector":"claudecode","session":"s-1","process":"` + runtime.GOOS + `:b:4242:100"},"session_start":true,"decision":{"deny":false}}`)
	request := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", bytes.NewReader(body))
		ctx := withAuthenticatedHookConnector(req.Context(), "claudecode")
		ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
		return req.WithContext(ctx)
	}
	ledger := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	commit := func() {
		t.Helper()
		data, err := enterprisepolicy.EncodeForeignHookRemovals(nil, []enterprisepolicy.ForeignHookRemoval{{
			Identity: identity, Connector: "claudecode", Path: "/home/alice/.claude/settings.json",
			At: time.Now().UTC().Format(time.RFC3339), Mark: runtime.GOOS + ":b:200",
		}}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ledger, data, 0o640); err != nil {
			t.Fatal(err)
		}
	}

	// A commit that owns the fence first must be visible to the exchange.
	unlock, err := enterprisepolicy.LockForeignHookRemovals(context.Background(), fence)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		recorder := httptest.NewRecorder()
		api.handleForeignHookSession(recorder, request())
		done <- recorder
	}()
	select {
	case response := <-done:
		unlock()
		t.Fatalf("exchange answered before the removal commit: %s", response.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	commit()
	unlock()
	select {
	case response := <-done:
		if !strings.Contains(response.Body.String(), `"deny":true`) {
			t.Fatalf("removal before exchange: %s", response.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("exchange did not answer after the commit")
	}

	// Reset the ledger, then pause an allow during Encode. The guardian's
	// exclusive commit must wait until that response has been written.
	if err := os.Remove(ledger); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	paused := pausedForeignHookResponse{ResponseWriter: recorder, entered: make(chan struct{}), resume: make(chan struct{})}
	answered := make(chan struct{})
	go func() { api.handleForeignHookSession(paused, request()); close(answered) }()
	select {
	case <-paused.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("allow did not reach its response write")
	}
	writerDone := make(chan func(), 1)
	go func() {
		unlock, err := enterprisepolicy.LockForeignHookRemovals(context.Background(), fence)
		if err == nil {
			writerDone <- unlock
		}
	}()
	select {
	case unlock := <-writerDone:
		unlock()
		close(paused.resume)
		t.Fatal("guardian commit overtook an allow response write")
	case <-time.After(100 * time.Millisecond):
	}
	close(paused.resume)
	<-answered
	select {
	case unlock := <-writerDone:
		commit()
		unlock()
	case <-time.After(3 * time.Second):
		t.Fatal("guardian did not acquire the fence after the response")
	}
}
