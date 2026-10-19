// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

func nativeModelOK() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"content":[{"type":"text","text":"answer"}]}`))}
}

func TestNativeModelAdapterCompleteProjectionAndHeartbeat(t *testing.T) {
	adapter, _, _, inspector := nativeModelFixture(t)
	body := `{"model":"claude-sonnet-test","max_tokens":128,"system":[{"type":"text","text":"system_marker"}],"tools":[{"name":"Bash","description":"definition_marker","input_schema":{"type":"object","properties":{"command":{"type":"string","description":"schema_marker"}}}}],"messages":[{"role":"user","content":"first_user_marker"},{"role":"assistant","content":[{"type":"text","text":"prior_assistant_marker"},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"command_marker"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"result_marker"},{"type":"text","text":"safe continuation"}]}]}`
	called := 0
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(req *http.Request) (*http.Response, error) {
		called++
		forwarded, err := io.ReadAll(req.Body)
		if err != nil || string(forwarded) != body {
			t.Errorf("private provider body changed or could not be read: %v", err)
		}
		return nativeModelOK(), nil
	}))
	rec := httptest.NewRecorder()
	adapter.ServeHTTP(rec, nativeModelRequest(body))
	if rec.Code != http.StatusOK || called != 1 || inspector.promptCalls != 1 {
		t.Fatalf("complete native prompt did not use shared proxy: status=%d upstream=%d scans=%d", rec.Code, called, inspector.promptCalls)
	}
	for _, marker := range []string{"system_marker", "definition_marker", "schema_marker", "first_user_marker",
		"prior_assistant_marker", "command_marker", "result_marker", "safe continuation"} {
		if !strings.Contains(inspector.lastContent, marker) {
			t.Fatalf("provider-visible %q absent from inspected text", marker)
		}
	}
	if len(inspector.lastMessages) != 1 || inspector.lastMessages[0].Content != inspector.lastContent {
		t.Fatal("managed message inspector did not receive the full native projection")
	}

	heartbeat := `{"model":"claude-sonnet-test","max_tokens":128,"messages":[{"role":"user","content":"Read HEARTBEAT.md. Reply HEARTBEAT_OK"}]}`
	projected, err := nativeAnthropicInspection([]byte(heartbeat))
	if err != nil || !isHeartbeatMessage(projected, nil) {
		t.Fatalf("heartbeat bypass fixture does not reach ordinary allowlist: %v", err)
	}
	inspector.setVerdict("prompt", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "native test block"})
	rec = httptest.NewRecorder()
	adapter.ServeHTTP(rec, nativeModelRequest(heartbeat))
	if called != 1 || inspector.promptCalls != 2 || rec.Header().Get("X-DefenseClaw-Blocked") != "true" {
		t.Fatalf("native heartbeat escaped prompt inspection: status=%d upstream=%d scans=%d", rec.Code, called, inspector.promptCalls)
	}
}

func TestNativeModelAdapterConnectorProfileExcludesOwner(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner bool
	}{{"no_process_owner", false}, {"per_user_gateway_owner", true}} {
		t.Run(tc.name, func(t *testing.T) {
			stubProfileSources(t)
			resetConnectorRuleCategories(t)
			withLocalPatternsRestored(t)
			if tc.owner {
				processOwnerProfileSubject = func() (profileSubject, bool) {
					return profileSubject{UserID: "1001"}, true
				}
			}
			packDir := filepath.Join(t.TempDir(), "claude")
			writeRulePackFixtureFile(t, packDir, "rules/marker.yaml", `version: 1
category: secret
rules:
  - id: NATIVE-CLAUDE-PROFILE
    pattern: "native_claude_profile_marker"
    title: native Claude profile fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
			cfg := &config.Config{}
			cfg.Guardrail.Enabled = true
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.BlockAt = "CRITICAL"
			cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
				"owner": {Mode: "observe"},
				"strict": {Connectors: map[string]config.PerConnectorGuardrailConfig{
					"claudecode": {Mode: "action", BlockAt: "HIGH", RulePackDir: packDir},
				}},
			}
			cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
				{Profile: "owner", Match: config.ProfileMatch{Users: []string{"1001"}}},
				{Profile: "strict", Match: config.ProfileMatch{Connectors: []string{"claudecode"}}},
			}
			api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
			profiles := api.guardrailProfileSet()
			if profiles == nil {
				t.Fatal("native profile fixture did not compile its profile set")
			}
			generation := &Generation{N: 1, Config: cfg, Profiles: profiles,
				Thresholds: buildThresholdTable(cfg, profiles)}
			adapter, _, _, _ := nativeModelFixture(t)
			adapter.proxy.generationSource = func() *Generation { return generation }
			adapter.proxy.inspector = NewGuardrailInspector("local", nil, nil)
			// A real generation must resolve the bound connector's HIGH level,
			// while an omitted scope remains at the profile's global CRITICAL.
			profileCtx := context.WithValue(context.Background(), nativeModelExchangeKey{},
				&nativeModelExchange{adapter: adapter, binding: adapter.grant.Binding})
			profileCtx = withPinnedGeneration(profileCtx, generation)
			profileCtx = withGuardrailProfile(profileCtx, profiles, adapter.grant.Binding.Connector)
			missingScope := requestThresholds(profileCtx)
			boundScope := requestThresholds(withThresholdConnector(profileCtx, adapter.grant.Binding.Connector))
			if thresholdConnectorFrom(profileCtx) != "" ||
				missingScope.Block != guardrailSeverityRank("CRITICAL") ||
				boundScope.Block != guardrailSeverityRank("HIGH") {
				t.Fatal("profile fixture did not distinguish missing and bound threshold connector scopes")
			}
			called := 0
			nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(*http.Request) (*http.Response, error) {
				called++
				return nativeModelOK(), nil
			}))
			for _, input := range []struct {
				name string
				body string
			}{
				{"current user", `{"model":"claude-sonnet-test","max_tokens":128,"messages":[{"role":"user","content":"native_claude_profile_marker"}]}`},
				{"earlier user history", `{"model":"claude-sonnet-test","max_tokens":128,"messages":[{"role":"user","content":"native_claude_profile_marker"},{"role":"assistant","content":"acknowledged"},{"role":"user","content":"safe continuation"}]}`},
				{"tool use input", `{"model":"claude-sonnet-test","max_tokens":128,"messages":[{"role":"user","content":"start"},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"native_claude_profile_marker"}}]},{"role":"user","content":"safe continuation"}]}`},
				{"tool result content", `{"model":"claude-sonnet-test","max_tokens":128,"messages":[{"role":"user","content":"start"},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"true"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"native_claude_profile_marker"},{"type":"text","text":"safe continuation"}]}]}`},
				{"system", `{"model":"claude-sonnet-test","max_tokens":128,"system":"native_claude_profile_marker","messages":[{"role":"user","content":"safe continuation"}]}`},
				{"tool schema", `{"model":"claude-sonnet-test","max_tokens":128,"tools":[{"name":"Bash","description":"run commands","input_schema":{"type":"object","properties":{"command":{"type":"string","description":"native_claude_profile_marker"}}}}],"messages":[{"role":"user","content":"safe continuation"}]}`},
			} {
				t.Run(input.name, func(t *testing.T) {
					rec := httptest.NewRecorder()
					adapter.ServeHTTP(rec, nativeModelRequest(input.body))
					if called != 0 || rec.Header().Get("X-DefenseClaw-Blocked") != "true" {
						t.Fatalf("bound Claude rule pack missed %s: status=%d upstream=%d", input.name, rec.Code, called)
					}
				})
			}
		})
	}
}

func TestNativeModelAdapterPrivateNotificationAndBlockState(t *testing.T) {
	adapter, _, _, inspector := nativeModelFixture(t)
	queue := NewNotificationQueue()
	queue.Push(SecurityNotification{SubjectType: "prompt", Reason: "foreign_session_notice"})
	adapter.proxy.notify = queue
	openClawPromptBlocks.mu.Lock()
	previous := append([]openClawPromptBlock(nil), openClawPromptBlocks.entries...)
	openClawPromptBlocks.entries = nil
	openClawPromptBlocks.mu.Unlock()
	t.Cleanup(func() {
		openClawPromptBlocks.mu.Lock()
		openClawPromptBlocks.entries = previous
		openClawPromptBlocks.mu.Unlock()
	})
	called := 0
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(req *http.Request) (*http.Response, error) {
		called++
		forwarded, err := io.ReadAll(req.Body)
		if err != nil || string(forwarded) != nativeModelTestBody {
			t.Errorf("foreign notification changed private upstream body: %v", err)
		}
		return nativeModelOK(), nil
	}))
	rec := httptest.NewRecorder()
	adapter.ServeHTTP(rec, nativeModelRequest(nativeModelTestBody))
	if rec.Code != http.StatusOK || called != 1 {
		t.Fatalf("private model request did not reach provider: status=%d upstream=%d", rec.Code, called)
	}
	inspector.setVerdict("prompt", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "private native block"})
	rec = httptest.NewRecorder()
	adapter.ServeHTTP(rec, nativeModelRequest(nativeModelTestBody))
	openClawPromptBlocks.mu.Lock()
	blocks := len(openClawPromptBlocks.entries)
	openClawPromptBlocks.mu.Unlock()
	if called != 1 || rec.Header().Get("X-DefenseClaw-Blocked") != "true" ||
		len(queue.ActiveNotifications()) != 1 || blocks != 0 {
		t.Fatalf("private block escaped its session: status=%d upstream=%d queue=%d openclaw=%d",
			rec.Code, called, len(queue.ActiveNotifications()), blocks)
	}
}

func TestNativeModelAdapterRequiresSelectedAnthropicAndPinnedModel(t *testing.T) {
	adapter, store, _, _ := nativeModelFixture(t)
	owner, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tc := range []struct {
		name   string
		change func(*sandboxruntime.ModelBrokerPolicy)
	}{
		{"different harness", func(s *sandboxruntime.ModelBrokerPolicy) { s.HarnessIdentity.Version = "another-claude" }},
		{"different profile", func(s *sandboxruntime.ModelBrokerPolicy) { s.Profile = "another-profile" }},
		{"different LLM", func(s *sandboxruntime.ModelBrokerPolicy) { s.LLM = config.OpenShellLLMOpenAI }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			substituted := adapter.grant
			tc.change(&substituted.Selection)
			if created, err := newNativeModelAdapter(owner, adapter.proxy, store, substituted); err == nil || created != nil {
				t.Fatal("same-generation selection field was substituted")
			}
		})
	}
	for _, llm := range []string{config.OpenShellLLMAuto, ""} {
		t.Run("resolved_"+string(llm), func(t *testing.T) {
			cfg := &config.Config{OpenShell: config.OpenShellConfig{Enabled: true, LLM: llm,
				Workdir: config.OpenShellWorkdirConfig{Mode: config.OpenShellWorkdirCopy}}}
			cfg.OpenShell.Egress.Allow = []string{"api.anthropic.com"}
			policy, _, err := sandboxruntime.ResolveExecutionPolicy(cfg, packs.Flags{Harness: "claudecode"},
				sandboxruntime.PolicyOptions{Authority: adapter.grant.Authority, Harness: adapter.grant.Selection.HarnessIdentity})
			if err != nil {
				t.Fatal(err)
			}
			grant := adapter.grant
			grant.Policy = policy
			grant.Selection, _ = policy.ModelBrokerPolicy()
			if grant.Selection.LLM != llm {
				t.Fatal("host policy lost its selected LLM")
			}
			if created, err := newNativeModelAdapter(owner, adapter.proxy, store, grant); err == nil || created != nil {
				t.Fatal("unselected provider route acquired a private model adapter")
			}
		})
	}
	called := 0
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(*http.Request) (*http.Response, error) {
		called++
		return nativeModelOK(), nil
	}))
	body := `{"model":"claude-other-model","max_tokens":128,"messages":[{"role":"user","content":"hello"}]}`
	rec := httptest.NewRecorder()
	adapter.ServeHTTP(rec, nativeModelRequest(body))
	if rec.Code < 400 || called != 0 {
		t.Fatalf("guest substituted host-selected model: status=%d upstream=%d", rec.Code, called)
	}
}

type nativeModelCompletionGate struct {
	*mockInspector
	entered chan struct{}
	release chan struct{}
}

func (gate *nativeModelCompletionGate) Inspect(ctx context.Context, direction, content string,
	messages []ChatMessage, model, mode string) *ScanVerdict {
	if direction == "completion" {
		close(gate.entered)
		<-gate.release
	}
	return gate.mockInspector.Inspect(ctx, direction, content, messages, model, mode)
}

type nativeModelObservedBody struct {
	input *strings.Reader
	eof   atomic.Bool
}

func (body *nativeModelObservedBody) Read(data []byte) (int, error) {
	count, err := body.input.Read(data)
	if err == io.EOF {
		body.eof.Store(true)
	}
	return count, err
}
func (*nativeModelObservedBody) Close() error { return nil }

type nativeModelCommitWriter struct {
	header  http.Header
	status  int
	body    bytes.Buffer
	flushes int
}

func (writer *nativeModelCommitWriter) Header() http.Header { return writer.header }
func (writer *nativeModelCommitWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
}
func (writer *nativeModelCommitWriter) Write(data []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.body.Write(data)
}
func (writer *nativeModelCommitWriter) Flush() { writer.flushes++ }

func nativeModelExpectAbort(t *testing.T, call func()) {
	t.Helper()
	defer func() {
		if got := recover(); got != http.ErrAbortHandler {
			t.Fatalf("expected downstream abort, got %v", got)
		}
	}()
	call()
}

func TestNativeModelAdapterRevocationBeforeBufferedOutput(t *testing.T) {
	adapter, _, authority, inspector := nativeModelFixture(t)
	gate := &nativeModelCompletionGate{mockInspector: inspector, entered: make(chan struct{}), release: make(chan struct{})}
	adapter.proxy.inspector = gate
	responseBody := &nativeModelObservedBody{input: strings.NewReader(`{"content":[{"type":"text","text":"answer"}]}`)}
	upstreamCalls := 0
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(*http.Request) (*http.Response, error) {
		upstreamCalls++
		response := nativeModelOK()
		response.Body = responseBody
		return response, nil
	}))
	sink := &nativeModelCommitWriter{header: make(http.Header)}
	outcome := make(chan any, 1)
	go func() {
		defer func() { outcome <- recover() }()
		adapter.ServeHTTP(sink, nativeModelRequest(nativeModelTestBody))
	}()
	released := false
	defer func() {
		if !released {
			close(gate.release)
		}
	}()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("completion inspector not reached after upstream buffering")
	}
	if !responseBody.eof.Load() {
		t.Fatal("completion inspection began before full upstream body read")
	}
	authority.Store(&sandboxruntime.PolicyAuthorityBinding{SnapshotID: "fixed-host-facts", Generation: 2})
	close(gate.release)
	released = true
	select {
	case got := <-outcome:
		if got != http.ErrAbortHandler {
			t.Fatalf("revocation after buffering did not abort downstream commit: %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoked completion did not terminate")
	}
	if upstreamCalls != 1 || sink.status != 0 || sink.body.Len() != 0 || sink.flushes != 0 {
		t.Fatalf("revoked turn committed output: upstream=%d status=%d bytes=%d flushes=%d",
			upstreamCalls, sink.status, sink.body.Len(), sink.flushes)
	}
}

func TestNativeModelWriterAbortAfterRevocation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before bool
		commit func(*nativeModelWriter)
	}{
		{"write_header", false, func(writer *nativeModelWriter) { writer.WriteHeader(http.StatusOK) }},
		{"write_after_headers", true, func(writer *nativeModelWriter) { _, _ = writer.Write([]byte("late")) }},
		{"flush_after_headers", true, func(writer *nativeModelWriter) { writer.Flush() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter, _, authority, _ := nativeModelFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sink := &nativeModelCommitWriter{header: make(http.Header)}
			writer := &nativeModelWriter{adapter: adapter, ctx: ctx, target: sink,
				header: make(http.Header), cancel: cancel}
			if tc.before {
				if n, err := writer.Write([]byte("first")); n != len("first") || err != nil {
					t.Fatalf("initial write failed: %d %v", n, err)
				}
				writer.Flush()
			}
			status, body, flushes := sink.status, sink.body.String(), sink.flushes
			authority.Store(&sandboxruntime.PolicyAuthorityBinding{SnapshotID: "fixed-host-facts", Generation: 2})
			nativeModelExpectAbort(t, func() { tc.commit(writer) })
			if sink.status != status || sink.body.String() != body || sink.flushes != flushes {
				t.Fatal("revoked writer changed downstream headers, body or flush count")
			}
		})
	}
}
