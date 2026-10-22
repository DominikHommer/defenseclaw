// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
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
	writeForeignHookRemovalFenceFiles(t, guardianDir)
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
		response := newDeadlineRecorder()
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

// deadlineRecorder is a ResponseRecorder whose connection can bound a
// write, as the connection of every gateway listener can.
type deadlineRecorder struct{ *httptest.ResponseRecorder }

func newDeadlineRecorder() deadlineRecorder { return deadlineRecorder{httptest.NewRecorder()} }

func (deadlineRecorder) SetWriteDeadline(time.Time) error { return nil }

type pausedForeignHookResponse struct {
	http.ResponseWriter
	entered chan struct{}
	resume  chan struct{}
}

func (w pausedForeignHookResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

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
	writeForeignHookRemovalFenceFiles(t, guardianDir)
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
	unlock, err := enterprisepolicy.LockForeignHookRemovalsDrain(context.Background(), guardianDir)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		recorder := httptest.NewRecorder()
		api.handleForeignHookSession(deadlineRecorder{recorder}, request())
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
	paused := pausedForeignHookResponse{ResponseWriter: deadlineRecorder{recorder}, entered: make(chan struct{}), resume: make(chan struct{})}
	answered := make(chan struct{})
	go func() { api.handleForeignHookSession(paused, request()); close(answered) }()
	select {
	case <-paused.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("allow did not reach its response write")
	}
	writerDone := make(chan func(), 1)
	go func() {
		unlock, err := enterprisepolicy.LockForeignHookRemovalsDrain(context.Background(), guardianDir)
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

// foreignHookPipeListener serves HTTP over synchronous in-memory pipes: a
// write blocks until the peer reads, as a socket write does once a client
// has stopped reading and the socket buffers are full.
type foreignHookPipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newForeignHookPipeListener() *foreignHookPipeListener {
	return &foreignHookPipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *foreignHookPipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *foreignHookPipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *foreignHookPipeListener) Addr() net.Addr { return &net.UnixAddr{Name: "pipe", Net: "pipe"} }

func (l *foreignHookPipeListener) dial() (net.Conn, error) {
	server, client := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
		_ = server.Close()
		_ = client.Close()
		return nil, net.ErrClosed
	}
}

// A client that stops reading a large allow, or reads it a byte at a time,
// must not hold the shared removal fence past foreignHookFencedWriteTimeout:
// the guardian's removal commit still takes the fence, another identity's
// exchange is still answered although the same identity has a second slow
// exchange queued, and neither slow client receives a complete allow.
func TestForeignHookSessionSlowAllowReaderDoesNotHoldTheFence(t *testing.T) {
	guardianDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
	writeForeignHookRemovalFenceFiles(t, guardianDir)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	alice, bob := "1001", "1002"
	if runtime.GOOS == "windows" {
		alice, bob = "S-1-5-21-1111-2222-3333-1001", "S-1-5-21-1111-2222-3333-1002"
	}
	listener := newForeignHookPipeListener()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := withAuthenticatedHookConnector(r.Context(), "claudecode")
		ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, r.Header.Get("X-Test-Identity"))
		// Every gateway listener reaches the handler through the metrics
		// middleware's writer.
		api.handleForeignHookSession(&statusWriter{ResponseWriter: w, status: http.StatusOK}, r.WithContext(ctx))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	// The allow echoes the caller's findings: far more than any server-side
	// write buffer holds.
	findings := make([]map[string]any, 200)
	for i := range findings {
		findings[i] = map[string]any{"connector": "claudecode", "scope": "project", "digest": "abcd", "allowed": true,
			"path": "/repo/" + strconv.Itoa(i) + "/" + strings.Repeat("a", 400)}
	}
	request := func(identity string, n int) *http.Request {
		t.Helper()
		data, err := json.Marshal(map[string]any{
			"key":           map[string]any{"connector": "claudecode", "session": "s-" + strconv.Itoa(n), "process": runtime.GOOS + ":b:4242:100"},
			"session_start": true,
			"decision":      map[string]any{"deny": false, "findings": findings},
		})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, "http://gateway/api/v1/foreign-hook-session/claudecode", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-Identity", identity)
		return req
	}

	// Alice's first client never reads; her second reads a byte at a time.
	stalled, err := listener.dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stalled.Close() })
	go func(req *http.Request) { _ = req.Write(stalled) }(request(alice, 1))
	trickle, err := listener.dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trickle.Close() })
	trickled := make(chan []byte, 1)
	go func(req *http.Request) {
		if err := req.Write(trickle); err != nil {
			trickled <- nil
			return
		}
		var got []byte
		one := make([]byte, 1)
		for {
			if _, err := trickle.Read(one); err != nil {
				trickled <- got
				return
			}
			got = append(got, one[0])
			time.Sleep(10 * time.Millisecond)
		}
	}(request(alice, 2))

	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		unlock, err := enterprisepolicy.LockForeignHookRemovalsDrain(ctx, guardianDir)
		cancel()
		if err != nil {
			break
		}
		unlock()
		if time.Now().After(deadline) {
			t.Fatal("no slow allow took the removal fence")
		}
		time.Sleep(time.Millisecond)
	}

	// The guardian's removal commit waits for at most one bounded write.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	unlock, err := enterprisepolicy.LockForeignHookRemovalsDrain(ctx, guardianDir)
	cancel()
	if err != nil {
		t.Fatalf("guardian removal commit could not take the fence past a slow allow: %v", err)
	}
	unlock()

	// Bob's exchange is answered within the fence wait, ahead of alice's
	// second slow exchange.
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) { return listener.dial() },
	}}
	t.Cleanup(client.CloseIdleConnections)
	response, err := client.Do(request(bob, 3))
	if err != nil {
		t.Fatal(err)
	}
	var decision enterprisepolicy.GuardDecision
	decodeErr := json.NewDecoder(response.Body).Decode(&decision)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || decodeErr != nil || decision.Deny || len(decision.Findings) != len(findings) {
		t.Fatalf("another identity's exchange behind a slow allow: status %d, decode %v, %+v", response.StatusCode, decodeErr, decision.Reason)
	}

	// The gateway cut both slow responses: the client that never read finds
	// the connection closed, and the slow reader got an incomplete allow.
	deadline = time.Now().Add(5 * time.Second)
	for {
		_ = stalled.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
		_, err := stalled.Write([]byte("\n"))
		if errors.Is(err, io.ErrClosedPipe) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the gateway kept a never-read allow open: %v", err)
		}
	}
	select {
	case got := <-trickled:
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(got)), nil)
		if err == nil {
			_, err = io.ReadAll(resp.Body)
		}
		if err == nil {
			t.Fatalf("a slow reader received a complete allow (%d bytes)", len(got))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the gateway kept a slowly read allow open")
	}
}

// A connection that cannot bound the write gets no allow while the fence
// is held: the call is refused and the fence is free at once. A denial
// needs no fence and is still answered.
func TestForeignHookSessionRefusesAnAllowItCannotBound(t *testing.T) {
	guardianDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
	writeForeignHookRemovalFenceFiles(t, guardianDir)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	identity := "1001"
	if runtime.GOOS == "windows" {
		identity = "S-1-5-21-1111-2222-3333-1001"
	}
	exchange := func(session string, deny bool) *httptest.ResponseRecorder {
		t.Helper()
		body := `{"key":{"connector":"claudecode","session":"` + session + `","process":"` + runtime.GOOS + `:b:4242:100"},"session_start":true,"decision":{"deny":` + strconv.FormatBool(deny) + `,"reason":"enterprise_foreign_hook_blocked: project hook"}}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", strings.NewReader(body))
		ctx := withAuthenticatedHookConnector(req.Context(), "claudecode")
		ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
		// A plain recorder, like a writer wrapper without Unwrap, cannot set
		// a write deadline.
		recorder := httptest.NewRecorder()
		api.handleForeignHookSession(recorder, req.WithContext(ctx))
		return recorder
	}
	allow := exchange("s-1", false)
	if allow.Code != http.StatusServiceUnavailable || !strings.Contains(allow.Body.String(), "foreign_hook_response_unbounded") || strings.Contains(allow.Body.String(), `"deny":false`) {
		t.Fatalf("unbounded allow: %d %s", allow.Code, allow.Body.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	unlock, err := enterprisepolicy.LockForeignHookRemovalsDrain(ctx, guardianDir)
	cancel()
	if err != nil {
		t.Fatalf("the refused allow kept the fence: %v", err)
	}
	unlock()
	if deny := exchange("s-2", true); deny.Code != http.StatusOK || !strings.Contains(deny.Body.String(), `"deny":true`) {
		t.Fatalf("denial: %d %s", deny.Code, deny.Body.String())
	}
}

// An atomic guardian commit can have the same length and mtime as the old
// ledger. Its new file identity must invalidate the cache under the fence.
func TestForeignHookRemovalCacheSeesEqualSizeEqualTimeReplacement(t *testing.T) {
	dir := t.TempDir()
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
	path := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsFile)
	at := time.Now().UTC().Format(time.RFC3339)
	makeLedger := func(identity string) []byte {
		t.Helper()
		data, err := enterprisepolicy.EncodeForeignHookRemovals(nil, []enterprisepolicy.ForeignHookRemoval{{
			Identity: identity, Connector: "claudecode", Path: "/home/alice/.claude/settings.json",
			At: at, Mark: runtime.GOOS + ":b:200",
		}}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	alice, bob := "1001", "1002"
	first, second := makeLedger(bob), makeLedger(alice)
	if len(first) != len(second) {
		t.Fatal("the replacement is not the same size")
	}
	if err := os.WriteFile(path, first, 0o640); err != nil {
		t.Fatal(err)
	}
	cache := &foreignHookRemovalCache{}
	if got, err := cache.forIdentity(dir, alice); err != nil || len(got) != 0 {
		t.Fatalf("first ledger = %+v, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "replacement")
	if err := os.WriteFile(tmp, second, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ReplaceFile(tmp, path); err != nil {
		t.Fatal(err)
	}
	if got, err := cache.forIdentity(dir, alice); err != nil || len(got) != 1 || got[0].Identity != alice {
		t.Fatalf("same-size and same-mtime removal was missed: %+v, %v", got, err)
	}
}

// writeForeignHookRemovalFenceFiles creates the guardian's lock files (the
// fence and the ledger lock) in dir.
func writeForeignHookRemovalFenceFiles(t *testing.T, dir string) {
	t.Helper()
	for _, name := range enterprisepolicy.ForeignHookRemovalFenceFiles() {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o640); err != nil {
			t.Fatal(err)
		}
	}
}

func foreignHookTestIdentities(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = strconv.Itoa(1001 + i)
		if runtime.GOOS == "windows" {
			out[i] = "S-1-5-21-1111-2222-3333-" + out[i]
		}
	}
	return out
}

func foreignHookAllowRequest(identity, session string) *http.Request {
	body := `{"key":{"connector":"claudecode","session":"` + session + `","process":"` + runtime.GOOS + `:b:4242:100"},"session_start":true,"decision":{"deny":false}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", strings.NewReader(body))
	ctx := withAuthenticatedHookConnector(req.Context(), "claudecode")
	ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
	return req.WithContext(ctx)
}

// Allows of two identities whose clients read slowly hold the removal fence
// together, and a third identity's exchange is answered at once: exchanges
// share the fence and only a guardian commit excludes them. The commit
// still waits for every allow being written.
func TestForeignHookSessionSlowAllowsOfOtherIdentitiesDoNotRefuseAnExchange(t *testing.T) {
	guardianDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
	writeForeignHookRemovalFenceFiles(t, guardianDir)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	ids := foreignHookTestIdentities(3)

	type slowAllow struct {
		recorder *httptest.ResponseRecorder
		paused   pausedForeignHookResponse
		resume   func()
		answered chan struct{}
	}
	slow := make([]slowAllow, 2)
	for i := range slow {
		recorder := httptest.NewRecorder()
		paused := pausedForeignHookResponse{ResponseWriter: deadlineRecorder{recorder}, entered: make(chan struct{}), resume: make(chan struct{})}
		slow[i] = slowAllow{recorder: recorder, paused: paused, resume: sync.OnceFunc(func() { close(paused.resume) }), answered: make(chan struct{})}
		t.Cleanup(slow[i].resume)
		go func(s slowAllow, identity string) {
			api.handleForeignHookSession(s.paused, foreignHookAllowRequest(identity, "s-slow"))
			close(s.answered)
		}(slow[i], ids[i])
	}
	for i, s := range slow {
		select {
		case <-s.paused.entered:
		case <-time.After(3 * time.Second):
			t.Fatalf("identity %d's allow did not reach its response write while another identity's allow was being written", i)
		}
		// WriteHeader ran before the paused Write in the handler's goroutine.
		if s.recorder.Code != http.StatusOK {
			t.Fatalf("identity %d was refused behind another identity's slow allow: %d", i, s.recorder.Code)
		}
	}

	third := make(chan deadlineRecorder, 1)
	go func() {
		response := newDeadlineRecorder()
		api.handleForeignHookSession(response, foreignHookAllowRequest(ids[2], "s-third"))
		third <- response
	}()
	select {
	case response := <-third:
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"deny":false`) {
			t.Fatalf("a third identity behind two slow allows: %d %s", response.Code, response.Body.String())
		}
	case <-time.After(foreignHookFenceWait):
		t.Fatal("a third identity's exchange waited on two slow allows of other identities")
	}

	commit := func() (func(), error) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		return enterprisepolicy.LockForeignHookRemovalsDrain(ctx, guardianDir)
	}
	for i, s := range slow {
		if unlock, err := commit(); err == nil {
			unlock()
			t.Fatalf("a guardian commit overtook %d allows being written", len(slow)-i)
		}
		s.resume()
		<-s.answered
		if s.recorder.Code != http.StatusOK || !strings.Contains(s.recorder.Body.String(), `"deny":false`) {
			t.Fatalf("slow allow %d: %d %s", i, s.recorder.Code, s.recorder.Body.String())
		}
	}
	unlock, err := commit()
	if err != nil {
		t.Fatalf("the guardian commit did not take the fence after the allows: %v", err)
	}
	unlock()
}

// slowForeignHookResponse takes delay to write each response, as a client
// that reads slowly but within the write deadline does.
type slowForeignHookResponse struct {
	http.ResponseWriter
	delay   time.Duration
	written *time.Time
}

func (w slowForeignHookResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w slowForeignHookResponse) Write(data []byte) (int, error) {
	time.Sleep(w.delay)
	n, err := w.ResponseWriter.Write(data)
	*w.written = time.Now()
	return n, err
}

// publishForeignHookRemovalsForTest replaces the ledger as the guardian
// does, with an atomic rename and no fence, removing the given identities'
// hooks.
func publishForeignHookRemovalsForTest(t *testing.T, guardianDir string, identities ...string) {
	t.Helper()
	removals := make([]enterprisepolicy.ForeignHookRemoval, 0, len(identities))
	for _, identity := range identities {
		removals = append(removals, enterprisepolicy.ForeignHookRemoval{
			Identity: identity, Connector: "claudecode", Path: "/home/user/.claude/settings.json",
			At: time.Now().UTC().Format(time.RFC3339), Mark: runtime.GOOS + ":b:200",
		})
	}
	data, err := enterprisepolicy.EncodeForeignHookRemovals(nil, removals, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(guardianDir, ".staged-ledger")
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ReplaceFile(tmp, filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)); err != nil {
		t.Fatal(err)
	}
}

// A guardian removal commit lands while exchanges of several identities
// arrive without a pause and overlap so the fence is never free. The
// guardian publishes at once and waits a bounded time only. No exchange of
// any identity is refused, every allow of the removed identity was written
// before the guardian finished, and its exchanges that start after the
// publication are denied.
func TestForeignHookSessionRemovalCommitLandsUnderSustainedExchanges(t *testing.T) {
	guardianDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
	writeForeignHookRemovalFenceFiles(t, guardianDir)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	ids := foreignHookTestIdentities(4)
	alice := ids[0]

	type outcome struct {
		identity string
		code     int
		allow    bool
		deny     bool
		started  time.Time
		written  time.Time
	}
	var mu sync.Mutex
	var outcomes []outcome
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i, identity := range ids {
		wg.Add(1)
		go func(i int, identity string) {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 20 * time.Millisecond)
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				recorder := httptest.NewRecorder()
				var written time.Time
				w := slowForeignHookResponse{ResponseWriter: deadlineRecorder{recorder}, delay: 80 * time.Millisecond, written: &written}
				started := time.Now()
				api.handleForeignHookSession(w, foreignHookAllowRequest(identity, "s-"+strconv.Itoa(n)))
				body := recorder.Body.String()
				mu.Lock()
				outcomes = append(outcomes, outcome{
					identity: identity, code: recorder.Code, started: started, written: written,
					allow: recorder.Code == http.StatusOK && strings.Contains(body, `"deny":false`),
					deny:  recorder.Code == http.StatusOK && strings.Contains(body, `"deny":true`),
				})
				mu.Unlock()
			}
		}(i, identity)
	}
	stopped := sync.OnceFunc(func() {
		close(stop)
		wg.Wait()
	})
	t.Cleanup(stopped)
	count := func(match func(outcome) bool) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, o := range outcomes {
			if match(o) {
				n++
			}
		}
		return n
	}
	waitFor := func(what string, n int, match func(outcome) bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for count(match) < n {
			if time.Now().After(deadline) {
				t.Fatalf("only %d of %d %s", count(match), n, what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor("exchanges served", 8, func(outcome) bool { return true })

	publishedAt := time.Now()
	publishForeignHookRemovalsForTest(t, guardianDir, alice)
	drained, err := enterprisepolicy.AwaitForeignHookRemovalExchanges(guardianDir)
	finishedAt := time.Now()
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := finishedAt.Sub(publishedAt); elapsed > enterprisepolicy.ForeignHookRemovalDrainWait+time.Second {
		t.Fatalf("sustained exchanges held the guardian for %v (drained %v)", elapsed, drained)
	}
	waitFor("of alice's exchanges after the publication denied", 3, func(o outcome) bool {
		return o.identity == alice && o.deny && o.started.After(publishedAt)
	})
	waitFor("exchanges of other identities after the guardian finished", 3, func(o outcome) bool {
		return o.identity != alice && o.started.After(finishedAt)
	})
	stopped()
	for i, o := range outcomes {
		if o.code != http.StatusOK {
			t.Fatalf("exchange %d of %s was refused (%d) around a removal commit", i, o.identity, o.code)
		}
		if o.identity != alice {
			if !o.allow {
				t.Fatalf("exchange %d of %s, whose hooks were not removed, was denied", i, o.identity)
			}
			continue
		}
		if o.allow && !o.written.Before(finishedAt) {
			t.Fatalf("alice's allow %d was written after the guardian finished the removal commit", i)
		}
		if o.allow && o.started.After(publishedAt) {
			t.Fatalf("alice's exchange %d started after the publication and was allowed", i)
		}
	}
}

// A pending removal blocks the new calls of the removed account only, at
// once: while the guardian waits for another account's allow being
// written, the removed account's new exchange is denied, a third account's
// is allowed, and neither waits. The guardian goes on when the allow is
// written.
func TestForeignHookSessionPendingRemovalDeniesOnlyTheRemovedAccountsNewCalls(t *testing.T) {
	guardianDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
	writeForeignHookRemovalFenceFiles(t, guardianDir)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	ids := foreignHookTestIdentities(3)
	alice, bob, carol := ids[0], ids[1], ids[2]

	recorder := httptest.NewRecorder()
	paused := pausedForeignHookResponse{ResponseWriter: deadlineRecorder{recorder}, entered: make(chan struct{}), resume: make(chan struct{})}
	resume := sync.OnceFunc(func() { close(paused.resume) })
	t.Cleanup(resume)
	answered := make(chan struct{})
	go func() {
		api.handleForeignHookSession(paused, foreignHookAllowRequest(alice, "s-held"))
		close(answered)
	}()
	select {
	case <-paused.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("alice's allow did not reach its response write")
	}

	publishForeignHookRemovalsForTest(t, guardianDir, bob)
	type awaitResult struct {
		drained bool
		err     error
	}
	awaited := make(chan awaitResult, 1)
	go func() {
		drained, err := enterprisepolicy.AwaitForeignHookRemovalExchanges(guardianDir)
		awaited <- awaitResult{drained, err}
	}()

	for _, want := range []struct {
		identity string
		deny     bool
	}{{bob, true}, {carol, false}, {bob, true}} {
		result := make(chan deadlineRecorder, 1)
		go func() {
			response := newDeadlineRecorder()
			api.handleForeignHookSession(response, foreignHookAllowRequest(want.identity, "s-later"))
			result <- response
		}()
		select {
		case response := <-result:
			if response.Code != http.StatusOK || strings.Contains(response.Body.String(), `"deny":true`) != want.deny {
				t.Fatalf("an exchange of %s while a removal was pending: %d %s", want.identity, response.Code, response.Body.String())
			}
		case <-time.After(foreignHookFenceWait):
			t.Fatalf("an exchange of %s waited on a pending removal", want.identity)
		}
	}
	select {
	case <-awaited:
		t.Fatal("the guardian went on while alice's allow was being written")
	default:
	}
	resume()
	<-answered
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"deny":false`) {
		t.Fatalf("alice's allow: %d %s", recorder.Code, recorder.Body.String())
	}
	select {
	case result := <-awaited:
		if result.err != nil || !result.drained {
			t.Fatalf("the guardian did not see the allow finish: drained %v, %v", result.drained, result.err)
		}
	case <-time.After(enterprisepolicy.ForeignHookRemovalDrainWait):
		t.Fatal("the guardian did not go on after the allow was written")
	}
}

// A fence the guardian would refuse, one with content, refuses the
// exchange too: the gateway must not allow from a ledger the guardian may
// have stopped updating.
func TestForeignHookSessionRefusesANonEmptyRemovalFence(t *testing.T) {
	guardianDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
	writeForeignHookRemovalFenceFiles(t, guardianDir)
	if err := os.WriteFile(filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFenceFile), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	response := newDeadlineRecorder()
	api.handleForeignHookSession(response, foreignHookAllowRequest(foreignHookTestIdentities(1)[0], "s-1"))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "foreign_hook_removal_fence_unavailable") || strings.Contains(response.Body.String(), `"deny":false`) {
		t.Fatalf("exchange with a non-empty fence: %d %s", response.Code, response.Body.String())
	}
}

// An allow is answered only within its hold after the exchange took the
// fence, because the guardian waits no longer than that for it: past the
// hold the call is refused, and the fence is free at once. A denial is not
// bound by the hold.
func TestForeignHookSessionAllowPastItsHoldIsRefused(t *testing.T) {
	if foreignHookFencedWriteTimeout >= enterprisepolicy.ForeignHookRemovalExchangeHold ||
		enterprisepolicy.ForeignHookRemovalExchangeHold >= enterprisepolicy.ForeignHookRemovalDrainWait {
		t.Fatal("the write timeout, the exchange hold and the guardian's drain wait are out of order")
	}
	guardianDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	previousHold := foreignHookExchangeHold
	foreignHookExchangeHold = 0
	t.Cleanup(func() {
		validateManagedGuardianAuthorization = previous
		foreignHookExchangeHold = previousHold
	})
	writeForeignHookRemovalFenceFiles(t, guardianDir)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	identity := foreignHookTestIdentities(1)[0]
	allow := newDeadlineRecorder()
	api.handleForeignHookSession(allow, foreignHookAllowRequest(identity, "s-1"))
	if allow.Code != http.StatusServiceUnavailable || !strings.Contains(allow.Body.String(), "foreign_hook_removal_fence_expired") || strings.Contains(allow.Body.String(), `"deny":false`) {
		t.Fatalf("allow past its hold: %d %s", allow.Code, allow.Body.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	unlock, err := enterprisepolicy.LockForeignHookRemovalsDrain(ctx, guardianDir)
	cancel()
	if err != nil {
		t.Fatalf("the refused allow kept the fence: %v", err)
	}
	unlock()
	body := `{"key":{"connector":"claudecode","session":"s-2","process":"` + runtime.GOOS + `:b:4242:100"},"session_start":true,"decision":{"deny":true,"reason":"enterprise_foreign_hook_blocked: project hook"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", strings.NewReader(body))
	reqCtx := withAuthenticatedHookConnector(req.Context(), "claudecode")
	reqCtx = context.WithValue(reqCtx, verifiedUserScopedIdentityContextKey{}, identity)
	deny := newDeadlineRecorder()
	api.handleForeignHookSession(deny, req.WithContext(reqCtx))
	if deny.Code != http.StatusOK || !strings.Contains(deny.Body.String(), `"deny":true`) {
		t.Fatalf("denial: %d %s", deny.Code, deny.Body.String())
	}
}
