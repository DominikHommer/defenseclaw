// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

type nativeModelRoundTrip func(*http.Request) (*http.Response, error)

func (fn nativeModelRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func nativeModelFixture(t *testing.T) (*nativeModelAdapter, *sandboxauth.FileStore, *atomic.Pointer[sandboxruntime.PolicyAuthorityBinding], *mockInspector) {
	t.Helper()
	store, err := sandboxauth.OpenFileStore(filepath.Join(t.TempDir(), "bindings.json"), sandboxauth.WithRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	identity := sandboxruntime.SessionIdentity{Owner: "host-owner", ID: "model-session", Name: "modelbox",
		Runtime: sandboxruntime.RuntimeIdentity{Runtime: sandboxruntime.Axis, Backend: "mxc", Driver: "bubblewrap",
			HostOS: "linux", ExecutionOS: "linux", Architecture: "amd64", Version: "fixed-test",
			Artifact: sandboxruntime.ArtifactIdentity{Kind: sandboxruntime.ExecutableBundle, Digest: "sha256:" + strings.Repeat("a", 64)}}}
	binding, token, err := store.Mint(sandboxauth.Spec{SandboxID: identity.ID, SandboxName: identity.Name,
		Connector: "claudecode", ExecutionOS: "linux", Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
		Routes: []sandboxauth.Route{sandboxauth.RouteHook}, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	authority := &atomic.Pointer[sandboxruntime.PolicyAuthorityBinding]{}
	authority.Store(&sandboxruntime.PolicyAuthorityBinding{SnapshotID: "fixed-host-facts", Generation: 1})
	cfg := &config.Config{OpenShell: config.OpenShellConfig{Enabled: true, LLM: config.OpenShellLLMAnthropic,
		Workdir: config.OpenShellWorkdirConfig{Mode: config.OpenShellWorkdirCopy}}}
	cfg.OpenShell.Egress.Allow = []string{"api.anthropic.com"}
	policy, _, err := sandboxruntime.ResolveExecutionPolicy(cfg, packs.Flags{Harness: "claudecode"}, sandboxruntime.PolicyOptions{
		Authority: *authority.Load(), Harness: sandboxruntime.HarnessIdentity{Version: "fixed-claude", HookContract: "fixed-hooks",
			Artifact: sandboxruntime.ArtifactIdentity{Kind: sandboxruntime.OCIImage, Digest: "sha256:" + strings.Repeat("b", 64)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	selection, ok := policy.ModelBrokerPolicy()
	if !ok {
		t.Fatal("resolved policy has no model broker selection")
	}
	spec := sandboxruntime.Spec{Identity: identity, Harness: "claudecode",
		HarnessIdentity: selection.HarnessIdentity, BindingID: binding.ID, CredentialProfile: nativeClaudeProfile}
	inspector := newMockInspector()
	proxy := newTestProxy(t, nil, inspector, "action")
	proxy.skipAuthForTest = false
	owner, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	adapter, err := newNativeModelAdapter(owner, proxy, store, nativeModelGrant{Identity: identity,
		Binding: binding, Bearer: token, Authority: *authority.Load(), Current: func() sandboxruntime.PolicyAuthorityBinding { return *authority.Load() },
		Policy: policy, Selection: selection, Spec: spec, Profile: nativeClaudeProfile,
		Endpoint: nativeClaudeEndpoint, Model: "claude-sonnet-test",
		MaxTokens: 512, Credential: "real-host-only-key"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		if err := adapter.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return adapter, store, authority, inspector
}

func nativeModelRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://guest.invalid/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

const nativeModelTestBody = `{"model":"claude-sonnet-test","max_tokens":128,"messages":[{"role":"user","content":"hello"}]}`

func nativeModelSetTransport(t *testing.T, adapter *nativeModelAdapter, upstream http.RoundTripper) {
	t.Helper()
	transport, ok := adapter.client.Transport.(*nativeModelTransport)
	if !ok {
		t.Fatal("private transport boundary missing")
	}
	transport.upstream = upstream
}

func TestNativeModelAdapterUsesGuardrailAndHostOnlyRoute(t *testing.T) {
	adapter, _, _, inspector := nativeModelFixture(t)
	called := 0
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(req *http.Request) (*http.Response, error) {
		called++
		if req.URL.String() != "https://api.anthropic.com/v1/messages" || req.Host != "api.anthropic.com" ||
			req.Header.Get("x-api-key") != "real-host-only-key" || req.Header.Get("Anthropic-Version") != "2023-06-01" ||
			req.Header.Get("X-AI-Auth") != "" || req.Header.Get("X-DC-Target-URL") != "" ||
			req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" || req.Header.Get("Proxy-Authorization") != "" {
			t.Error("provider request used guest routing, auth, or identity headers")
		}
		identity := AgentIdentityFromContext(req.Context())
		if identity.AgentInstanceID != adapter.grant.Identity.ID ||
			identity.SidecarInstanceID != string(sandboxConnectorInstanceID(adapter.grant.Binding)) ||
			sandboxSessionStateKey(req.Context(), "same") == "same" ||
			!strings.Contains(sandboxSessionStateKey(req.Context(), "same"), adapter.grant.Binding.ID) {
			t.Error("private model call lost its owned session identity")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"},
			"Set-Cookie": {"should-not-reach-guest=1"}}, Body: io.NopCloser(strings.NewReader(`{"content":[{"type":"text","text":"answer"}]}`))}, nil
	}))
	req := nativeModelRequest(nativeModelTestBody)
	req = req.WithContext(ContextWithAgentIdentity(req.Context(), AgentIdentity{AgentID: "guest-forgery", AgentInstanceID: "other-session"}))
	req.Host = "attacker.example"
	for name, value := range map[string]string{"X-DC-Target-URL": "https://attacker.example", "X-AI-Auth": "Bearer guest-key",
		"Authorization": "Bearer guest-key", "x-api-key": "guest-key", "Proxy-Authorization": "Basic guest", "Cookie": "session=guest",
		"Anthropic-Version": "guest-version"} {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	adapter.ServeHTTP(rec, req)
	if called != 1 || rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "answer") ||
		rec.Header().Get("Set-Cookie") != "" || inspector.promptCalls != 1 {
		t.Fatalf("private request did not use inspected provider path: calls=%d status=%d prompt_scans=%d", called, rec.Code, inspector.promptCalls)
	}
}

func TestNativeModelAdapterInspectsTextBlocksInMultiTurnHistory(t *testing.T) {
	adapter, _, _, inspector := nativeModelFixture(t)
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"content":[{"type":"text","text":"answer"}]}`))}, nil
	}))
	request := nativeModelRequest(`{"model":"claude-sonnet-test","max_tokens":128,"messages":[{"role":"user","content":"first"},{"role":"assistant","content":[{"type":"text","text":"prior answer"}]},{"role":"user","content":[{"type":"text","text":"safe"},{"type":"text","text":"continuation"}]}]}`)
	rec := httptest.NewRecorder()
	adapter.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK || inspector.promptCalls != 1 ||
		!strings.Contains(inspector.lastContent, "first") ||
		!strings.Contains(inspector.lastContent, "prior answer") ||
		!strings.Contains(inspector.lastContent, "safe\ncontinuation") ||
		len(inspector.lastMessages) != 1 || inspector.lastMessages[0].Content != inspector.lastContent {
		t.Fatalf("whole text-block history missed shared prompt inspection: status=%d scans=%d text=%q", rec.Code, inspector.promptCalls, inspector.lastContent)
	}
}

func TestNativeModelAdapterRefusesStaleAuthorityBindingAndMalformedInput(t *testing.T) {
	adapter, store, authority, _ := nativeModelFixture(t)
	called := 0
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(req *http.Request) (*http.Response, error) {
		called++
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	}))
	for _, tc := range []struct {
		name string
		req  *http.Request
	}{
		{"wrong path", httptest.NewRequest(http.MethodPost, "http://guest.invalid/v1/responses", strings.NewReader(nativeModelTestBody))},
		{"query", httptest.NewRequest(http.MethodPost, "http://guest.invalid/v1/messages?target=evil", strings.NewReader(nativeModelTestBody))},
		{"invalid body", nativeModelRequest(`{"model":"x"}`)},
		{"duplicate model", nativeModelRequest(`{"model":"inspected","Model":"executed","messages":[{"role":"user","content":"hello"}]}`)},
		{"nested duplicate", nativeModelRequest(`{"model":"x","messages":[{"role":"user","content":"hello","Content":"other"}]}`)},
		{"uninspectable user", nativeModelRequest(`{"model":"x","messages":[{"role":"user","content":[{"type":"tool_result","content":"hidden"}]}]}`)},
		{"tool result missing tool_use_id", nativeModelRequest(`{"model":"claude-sonnet-test","max_tokens":128,"messages":[{"role":"user","content":[{"type":"text","text":"safe"},{"type":"tool_result","content":"hidden"}]}]}`)},
		{"excessive tokens", nativeModelRequest(`{"model":"claude-sonnet-test","max_tokens":999999,"messages":[{"role":"user","content":"safe"}]}`)},
		{"large body", nativeModelRequest(strings.Repeat("a", nativeModelRequestLimit+1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			adapter.ServeHTTP(rec, tc.req)
			if rec.Code < 400 || called != 0 {
				t.Fatalf("malformed request reached upstream: status=%d calls=%d", rec.Code, called)
			}
		})
	}
	authority.Store(&sandboxruntime.PolicyAuthorityBinding{SnapshotID: "fixed-host-facts", Generation: 2})
	rec := httptest.NewRecorder()
	adapter.ServeHTTP(rec, nativeModelRequest(nativeModelTestBody))
	if rec.Code != http.StatusServiceUnavailable || called != 0 {
		t.Fatalf("rotated authority reached upstream: status=%d calls=%d", rec.Code, called)
	}
	authority.Store(&adapter.grant.Authority)
	if err := store.Revoke(adapter.grant.Binding.ID); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	adapter.ServeHTTP(rec, nativeModelRequest(nativeModelTestBody))
	if rec.Code != http.StatusServiceUnavailable || called != 0 {
		t.Fatalf("revoked binding reached upstream: status=%d calls=%d", rec.Code, called)
	}
}

func TestNativeModelAdapterConstructorRejectsForeignOrUnpinnedGrant(t *testing.T) {
	adapter, store, _, _ := nativeModelFixture(t)
	owner, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tc := range []struct {
		name   string
		change func(*nativeModelGrant)
	}{
		{"foreign session", func(g *nativeModelGrant) { g.Identity.ID = "another-session" }},
		{"foreign binding", func(g *nativeModelGrant) { g.Binding.SandboxID = "another-session" }},
		{"wrong token", func(g *nativeModelGrant) { g.Bearer = "not-a-token" }},
		{"unreviewed profile", func(g *nativeModelGrant) { g.Profile = "defenseclaw-claude-oauth" }},
		{"target substitution", func(g *nativeModelGrant) { g.Endpoint = "https://attacker.example" }},
		{"empty secret", func(g *nativeModelGrant) { g.Credential = "" }},
		{"header injection secret", func(g *nativeModelGrant) { g.Credential = "key\r\nX-Other: stolen" }},
		{"stale authority", func(g *nativeModelGrant) { g.Authority.Generation++ }},
		{"selection authority mismatch", func(g *nativeModelGrant) { g.Selection.Authority.Generation++ }},
		{"policy authority mismatch", func(g *nativeModelGrant) { g.Policy = nil }},
		{"unselected model", func(g *nativeModelGrant) { g.Model = "" }},
		{"oversized model pin", func(g *nativeModelGrant) { g.Model = strings.Repeat("x", 257) }},
		{"token ceiling removed", func(g *nativeModelGrant) { g.MaxTokens = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := adapter.grant
			tc.change(&grant)
			if created, err := newNativeModelAdapter(owner, adapter.proxy, store, grant); err == nil || created != nil {
				t.Fatal("foreign or unpinned model grant admitted")
			}
		})
	}
}

func TestNativeModelAdapterRefusesOfflineHostPolicy(t *testing.T) {
	adapter, store, _, _ := nativeModelFixture(t)
	cfg := &config.Config{OpenShell: config.OpenShellConfig{Enabled: true, LLM: config.OpenShellLLMNone,
		Workdir: config.OpenShellWorkdirConfig{Mode: config.OpenShellWorkdirCopy}}}
	cfg.OpenShell.Egress.Allow = []string{"api.anthropic.com"}
	policy, _, err := sandboxruntime.ResolveExecutionPolicy(cfg, packs.Flags{Harness: "claudecode"}, sandboxruntime.PolicyOptions{
		Authority: adapter.grant.Authority, Offline: true,
		Harness: sandboxruntime.HarnessIdentity{Version: "fixed-claude", HookContract: "fixed-hooks",
			Artifact: sandboxruntime.ArtifactIdentity{Kind: sandboxruntime.OCIImage, Digest: "sha256:" + strings.Repeat("b", 64)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := adapter.grant
	grant.Policy = policy
	grant.Selection, _ = policy.ModelBrokerPolicy()
	owner, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if created, err := newNativeModelAdapter(owner, adapter.proxy, store, grant); err == nil || created != nil {
		t.Fatal("offline host policy admitted model egress")
	}
}

func TestNativeModelAdapterCancelAndOutputLimit(t *testing.T) {
	adapter, _, _, _ := nativeModelFixture(t)
	entered := make(chan struct{})
	var once sync.Once
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(req *http.Request) (*http.Response, error) {
		once.Do(func() { close(entered) })
		<-req.Context().Done()
		return nil, req.Context().Err()
	}))
	finished := make(chan any, 1)
	go func() {
		defer func() { finished <- recover() }()
		adapter.ServeHTTP(httptest.NewRecorder(), nativeModelRequest(nativeModelTestBody))
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("provider path was not entered")
	}
	ctx, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if err := adapter.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case caught := <-finished:
		if caught != nil && caught != http.ErrAbortHandler {
			t.Fatalf("owner close produced unexpected panic: %v", caught)
		}
	case <-time.After(time.Second):
		t.Fatal("active provider request survived owner close")
	}
	limitAdapter, _, _, _ := nativeModelFixture(t)
	writer := &nativeModelWriter{adapter: limitAdapter, ctx: context.Background(), target: httptest.NewRecorder(), header: make(http.Header), cancel: func() {}}
	if n, err := writer.Write(make([]byte, nativeModelOutputLimit)); n != nativeModelOutputLimit || err != nil {
		t.Fatalf("bounded output failed: n=%d err=%v", n, err)
	}
	if n, err := writer.Write([]byte("more")); n != 0 || !errors.Is(err, errNativeModelOutputLimit) || !writer.limited {
		t.Fatalf("output limit did not close: n=%d err=%v", n, err)
	}
}

type nativeModelBlockingBody struct {
	entered   chan struct{}
	closed    chan struct{}
	once      sync.Once
	closeOnce sync.Once
}

func (body *nativeModelBlockingBody) Read([]byte) (int, error) {
	body.once.Do(func() { close(body.entered) })
	<-body.closed
	return 0, io.EOF
}

func (body *nativeModelBlockingBody) Close() error {
	body.closeOnce.Do(func() { close(body.closed) })
	return nil
}

func TestNativeModelAdapterCloseReleasesStalledRequestBody(t *testing.T) {
	adapter, _, _, _ := nativeModelFixture(t)
	body := &nativeModelBlockingBody{entered: make(chan struct{}), closed: make(chan struct{})}
	request := nativeModelRequest(nativeModelTestBody)
	request.Body = body
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		adapter.ServeHTTP(httptest.NewRecorder(), request)
	}()
	select {
	case <-body.entered:
	case <-time.After(time.Second):
		t.Fatal("request body was not read")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := adapter.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("stalled body survived owner close")
	}
}

func TestNativeModelAdapterLimitsConcurrentRequests(t *testing.T) {
	adapter, _, _, _ := nativeModelFixture(t)
	entered := make(chan struct{}, nativeModelInFlight)
	release := make(chan struct{})
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(req *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"content":[{"type":"text","text":"done"}]}`))}, nil
	}))
	var workers sync.WaitGroup
	for range nativeModelInFlight {
		workers.Add(1)
		go func() {
			defer workers.Done()
			adapter.ServeHTTP(httptest.NewRecorder(), nativeModelRequest(nativeModelTestBody))
		}()
	}
	for range nativeModelInFlight {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("concurrent request did not enter provider")
		}
	}
	rec := httptest.NewRecorder()
	adapter.ServeHTTP(rec, nativeModelRequest(nativeModelTestBody))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("unbounded model admission: status=%d", rec.Code)
	}
	close(release)
	workers.Wait()
}

func TestNativeModelAdapterCapsUpstreamBeforeProxyBuffering(t *testing.T) {
	adapter, _, _, _ := nativeModelFixture(t)
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(strings.Repeat("x", nativeModelOutputLimit+1)))}, nil
	}))
	rec := httptest.NewRecorder()
	adapter.ServeHTTP(rec, nativeModelRequest(nativeModelTestBody))
	if rec.Code != http.StatusBadGateway || rec.Body.Len() > 1024 {
		t.Fatalf("oversized provider response appeared successful: status=%d bytes=%d", rec.Code, rec.Body.Len())
	}
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"},
			"X-Oversized": {strings.Repeat("h", nativeModelHeaderLimit+1)}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	}))
	rec = httptest.NewRecorder()
	adapter.ServeHTTP(rec, nativeModelRequest(nativeModelTestBody))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("oversized provider headers appeared successful: status=%d", rec.Code)
	}
}

type nativeModelStalledStream struct {
	first  atomic.Bool
	closed chan struct{}
	once   sync.Once
}

func (body *nativeModelStalledStream) Read(buf []byte) (int, error) {
	if !body.first.Swap(true) {
		return copy(buf, []byte("data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"first\"}}\n\n")), nil
	}
	<-body.closed
	return 0, errors.New("closed stream")
}

func (body *nativeModelStalledStream) Close() error {
	body.once.Do(func() { close(body.closed) })
	return nil
}

func TestNativeModelAdapterRotatedAuthorityAbortsStream(t *testing.T) {
	adapter, _, authority, _ := nativeModelFixture(t)
	body := &nativeModelStalledStream{closed: make(chan struct{})}
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: body}, nil
	}))
	finished := make(chan any, 1)
	go func() {
		defer func() { finished <- recover() }()
		adapter.ServeHTTP(httptest.NewRecorder(), nativeModelRequest(nativeModelTestBody))
	}()
	// Wait for the shared proxy to own the stream before rotating authority.
	for deadline := time.Now().Add(time.Second); !body.first.Load() && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if !body.first.Load() {
		t.Fatal("shared stream was not entered")
	}
	authority.Store(&sandboxruntime.PolicyAuthorityBinding{SnapshotID: "fixed-host-facts", Generation: 2})
	select {
	case caught := <-finished:
		if caught != http.ErrAbortHandler {
			t.Fatalf("rotated stream did not abort: %v", caught)
		}
	case <-time.After(time.Second):
		t.Fatal("rotated authority did not cancel stalled stream")
	}
}
