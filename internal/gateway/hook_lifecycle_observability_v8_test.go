// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

type storedHookLifecycleV8 struct {
	bucket     string
	eventName  string
	generation int64
	projected  map[string]any
	body       map[string]any
}

type hookLifecycleNilStartRuntime struct {
	lifecycleV8Runtime
}

func (*hookLifecycleNilStartRuntime) StartAgentTransitionTrace(
	context.Context,
	observability.SpanAgentTransitionInput,
) (context.Context, *observabilityruntime.AgentTransitionTrace, error) {
	return nil, nil, nil
}

func readStoredHookLifecycleV8(t *testing.T, path string) []storedHookLifecycleV8 {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT bucket, event_name, COALESCE(generation,0), projected_record_json
		FROM audit_events WHERE bucket IN ('agent.lifecycle','tool.activity')
		AND event_name IN ('session_start','session_end','subagent_start','subagent_stop',
		'turn_start','turn_end','tool_start','tool_end','compact_start','compact_end','event')
		ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []storedHookLifecycleV8
	for rows.Next() {
		var item storedHookLifecycleV8
		var raw string
		if err := rows.Scan(&item.bucket, &item.eventName, &item.generation, &raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(raw), &item.projected); err != nil {
			t.Fatalf("decode projected hook lifecycle: %v", err)
		}
		body, ok := item.projected["body"].(map[string]any)
		if !ok {
			t.Fatalf("projected hook lifecycle has no body: %#v", item.projected)
		}
		item.body = body
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func bindHookLifecycleV8(t *testing.T, api *APIServer, emitter sidecarRuntimeEmitter) {
	t.Helper()
	api.bindObservabilityV8Runtimes(emitter, nil, nil, nil)
}

func hookLifecycleTestMeta(event string) llmEventMeta {
	state := "active"
	outcome := "attempted"
	phase := "session"
	switch event {
	case "session_end", "subagent_stop", "turn_end":
		state, outcome, phase = "completed", "completed", "completed"
	case "tool_end":
		state, outcome, phase = "active", "completed", "planning"
	case "compact_end":
		state, outcome, phase = "active", "completed", "maintenance"
	case "event":
		state, outcome, phase = "observed", "", "observed"
	case "turn_start":
		phase = "planning"
	case "tool_start":
		phase = "tool"
	case "compact_start":
		phase = "maintenance"
	}
	return llmEventMeta{
		Source: "codex", Provider: "openai", Model: "gpt-5", SessionID: "session-1",
		RequestID: "request-1", RunID: "run-1", TurnID: "turn-1",
		AgentID: "agent-root", AgentName: "root", AgentType: "codex",
		RootAgentID: "agent-root", LineageProvenance: "reported", RootSessionID: "session-1",
		LifecycleID: "lifecycle-1", ExecutionID: "execution-1", LifecycleEvent: event,
		LifecycleState: state, LifecycleOutcome: outcome, Phase: phase,
		OperationID: "operation-1", Sequence: 1, ToolName: "shell", ToolID: "tool-call-1",
	}
}

func TestHookLifecycleV8EndFailureKeepsInboundCorrelation(t *testing.T) {
	api, _ := bindHookModelV8Runtime(t, []string{"traces"})
	failing := &hookGeneratedSpanEndFailureRuntime{
		lifecycleV8Runtime: api.observabilityV8LifecycleRuntime(),
		failTransitionEnd:  true,
	}
	api.bindObservabilityV8Lifecycle(failing)
	inbound := t.Context()

	correlated := api.emitHookLifecycleTransitionSpan(
		inbound,
		hookLifecycleTestMeta(observability.TelemetryEventSessionStart),
	)

	if !failing.transitionAborted {
		t.Fatal("transition End failure was not injected")
	}
	if correlated != inbound {
		t.Fatal("aborted transition returned generated correlation instead of inbound context")
	}
}

func TestHookLifecycleV8NilStartedContextKeepsInboundCorrelation(t *testing.T) {
	api := &APIServer{}
	api.bindObservabilityV8Lifecycle(&hookLifecycleNilStartRuntime{})
	inbound := t.Context()

	correlated := api.emitHookLifecycleTransitionSpan(
		inbound,
		hookLifecycleTestMeta(observability.TelemetryEventSessionStart),
	)

	if correlated != inbound {
		t.Fatalf("nil started context returned correlation=%v want inbound", correlated)
	}
}

func TestHookLifecycleV8UsesExactRegisteredFamilyForEveryNormalizedEvent(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	bindHookLifecycleV8(t, api, fixture.runtime)
	events := []string{
		"session_start", "session_end", "subagent_start", "subagent_stop",
		"turn_start", "turn_end", "tool_start", "tool_end",
		"compact_start", "compact_end", "event",
	}
	for _, event := range events {
		meta := hookLifecycleTestMeta(event)
		if got := api.emitHookLifecycleEvent(t.Context(), meta); got != hookLifecycleV8Persisted {
			t.Fatalf("event %q emission=%d", event, got)
		}
	}
	rows := readStoredHookLifecycleV8(t, fixture.path)
	if len(rows) != len(events) {
		t.Fatalf("rows=%d want=%d: %#v", len(rows), len(events), rows)
	}
	for index, event := range events {
		wantBucket := string(observability.BucketAgentLifecycle)
		if event == "tool_start" || event == "tool_end" {
			wantBucket = string(observability.BucketToolActivity)
		}
		if rows[index].eventName != event || rows[index].bucket != wantBucket {
			t.Errorf("row %d=%s/%s want=%s/%s", index, rows[index].bucket, rows[index].eventName, wantBucket, event)
		}
	}
}

func TestHookLifecycleV8ProducerCutoverRoutesLifecycleCanonically(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	bindHookLifecycleV8(t, api, fixture.runtime)
	api.emitCodexHookLLMEvent(t.Context(), codexHookRequest{
		HookEventName: "SessionStart", SessionID: "codex-session", AgentID: "codex-root",
		AgentType: "codex", Payload: map[string]any{"root_agent_id": "codex-root", "source": "startup"},
	}, nil, nil)
	api.emitCodexHookLLMEvent(t.Context(), codexHookRequest{
		HookEventName: "UserPromptSubmit", SessionID: "codex-session", TurnID: "codex-turn",
		AgentID: "codex-root", AgentType: "codex", Prompt: "preserve the prompt event",
		Payload: map[string]any{"root_agent_id": "codex-root"},
	}, nil, []byte(`{"prompt":"preserve the prompt event"}`))
	api.emitAgentHookLLMEvent(t.Context(), agentHookRequest{
		ConnectorName: "cursor", HookEventName: "SessionStart", SessionID: "cursor-session",
		AgentID: "cursor-root", AgentName: "cursor", AgentType: "cursor",
		Payload: map[string]any{"root_agent_id": "cursor-root", "source": "startup"},
	}, nil)
	api.emitClaudeCodeHookLLMEvent(t.Context(), claudeCodeHookRequest{
		HookEventName: "SessionStart", SessionID: "claude-session", AgentID: "claude-root",
		AgentType: "claudecode", Payload: map[string]any{"root_agent_id": "claude-root", "source": "startup"},
	}, nil, nil)

	rows := readStoredHookLifecycleV8(t, fixture.path)
	if len(rows) != 4 {
		t.Fatalf("canonical lifecycle rows=%d want 4", len(rows))
	}
}

func TestCodexHookInfersRealNestedSpawnOrderWithoutSubagentStart(t *testing.T) {
	fixture := newSignedSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	bindHookLifecycleV8(t, api, fixture.runtime)
	rootID := stableLLMEventID("agent", "codex", "real-codex-nested-session", "root")
	const (
		sessionID = "real-codex-nested-session"
		parentID  = "real-parent"
		childID   = "real-child"
		grandID   = "real-grandchild"
		message   = "grandchild update preserved"
		childDone = "child outcome preserved"
		grandDone = "grandchild outcome preserved"
	)
	api.emitCodexHookLLMEvent(t.Context(), codexHookRequest{
		HookEventName: "SessionStart", SessionID: sessionID, AgentID: rootID, AgentType: "codex",
		Payload: map[string]any{"root_agent_id": rootID, "agent_depth": 0, "source": "startup"},
	}, nil, nil)
	api.emitCodexHookLLMEvent(t.Context(), codexHookRequest{
		HookEventName: "SubagentStart", SessionID: sessionID, AgentID: parentID, AgentType: "subagent",
		Payload: map[string]any{
			"root_agent_id": rootID, "parent_agent_id": rootID, "agent_depth": 1,
			"task_name": "/root/real-parent",
		},
	}, nil, nil)

	emitTool := func(agentID, turnID, callID, event, tool string, input map[string]any, response any) {
		api.emitCodexHookLLMEvent(t.Context(), codexHookRequest{
			HookEventName: event, SessionID: sessionID, TurnID: turnID,
			AgentID: agentID, AgentType: "subagent", ToolName: tool, ToolUseID: callID,
			ToolInput: input, ToolResponse: response,
			Payload: map[string]any{"tool_call_id": callID, "tool_name": tool},
		}, nil, nil)
	}
	spawn := func(parentAgentID, turnID, callID, taskName string) {
		input := map[string]any{"task_name": taskName}
		emitTool(parentAgentID, turnID, callID, "PreToolUse", "collaboration.spawn_agent", input, nil)
		// Codex 0.136 reports only task_name here; no child UUID or task alias
		// appears on the child's later hook.
		emitTool(parentAgentID, turnID, callID, "PostToolUse", "collaboration.spawn_agent", input,
			map[string]any{"task_name": taskName})
	}

	spawn(parentID, "parent-spawn-turn", "parent-spawn-call", "/root/real-parent/real-child")
	// The child's first hook is a tool event. There is intentionally no
	// SubagentStart and no task_name in this delivery.
	emitTool(childID, "child-bash-turn", "child-bash-call", "PreToolUse", "Bash",
		map[string]any{"command": "printf child"}, nil)
	emitTool(childID, "child-bash-turn", "child-bash-call", "PostToolUse", "Bash",
		map[string]any{"command": "printf child"}, "child")
	spawn(childID, "child-spawn-turn", "child-spawn-call", "/root/real-parent/real-child/real-grandchild")
	// The grandchild also begins with a tool event and omits SubagentStart.
	emitTool(grandID, "grand-bash-turn", "grand-bash-call", "PreToolUse", "Bash",
		map[string]any{"command": "printf grandchild"}, nil)
	emitTool(grandID, "grand-bash-turn", "grand-bash-call", "PostToolUse", "Bash",
		map[string]any{"command": "printf grandchild"}, "grandchild")
	emitTool(grandID, "grand-message-turn", "grand-message-call", "PreToolUse", "collaboration.send_message",
		map[string]any{"target": "/root", "message": message}, nil)
	emitTool(grandID, "grand-message-turn", "grand-message-call", "PostToolUse", "collaboration.send_message",
		map[string]any{"target": "/root", "message": message}, map[string]any{"delivered": true})

	// Real Codex stops repeat the child UUID but flatten parent/root/depth. The
	// retained inferred lifecycle must remain authoritative.
	api.emitCodexHookLLMEvent(t.Context(), codexHookRequest{
		HookEventName: "SubagentStop", SessionID: sessionID, TurnID: "grand-stop",
		AgentID: grandID, AgentType: "subagent", LastAssistantMessage: grandDone,
		Payload: map[string]any{"root_agent_id": rootID, "parent_session_id": sessionID},
	}, nil, nil)
	api.emitCodexHookLLMEvent(t.Context(), codexHookRequest{
		HookEventName: "SubagentStop", SessionID: sessionID, TurnID: "child-stop",
		AgentID: childID, AgentType: "subagent", LastAssistantMessage: childDone,
		Payload: map[string]any{"root_agent_id": rootID, "parent_session_id": sessionID},
	}, nil, nil)
	for _, stop := range []struct {
		agent, parent string
		depth         int
	}{
		{agent: childID, parent: parentID, depth: 2},
		{agent: grandID, parent: childID, depth: 3},
	} {
		decision, _, ok := api.hookDecisionMeta(t.Context(), agentHookRequest{
			ConnectorName: "codex", HookEventName: "SubagentStop", SessionID: sessionID,
			AgentID: stop.agent, AgentType: "subagent",
			Payload: map[string]any{"root_agent_id": rootID, "parent_session_id": sessionID},
		})
		if !ok || decision.RootAgentID != rootID || decision.ParentAgentID != stop.parent ||
			decision.AgentDepth != stop.depth {
			t.Fatalf("stop decision lost recursive lineage agent=%s present=%t meta=%+v", stop.agent, ok, decision)
		}
	}

	for _, want := range []struct {
		agent, parent string
		depth         int
	}{
		{parentID, rootID, 1},
		{childID, parentID, 2},
		{grandID, childID, 3},
	} {
		snapshot, ok := api.hookLifecycleSnapshot("codex", sessionID, want.agent)
		if !ok || snapshot.RootAgentID != rootID || snapshot.ParentAgentID != want.parent ||
			snapshot.AgentDepth != want.depth || snapshot.LineageProvenance == "" {
			t.Fatalf("four-level snapshot agent=%s present=%t meta=%+v", want.agent, ok, snapshot)
		}
	}
	if count := hookSpawnIntentCount(api); count != 0 {
		t.Fatalf("real-order spawn intents remaining=%d want=0", count)
	}

	starts := map[string]int{}
	stops := map[string]int{}
	ownedTools := map[string]bool{}
	eventsByAgent := map[string][]string{}
	for _, row := range readStoredHookLifecycleV8(t, fixture.path) {
		agentID := fmt.Sprint(row.body["gen_ai.agent.id"])
		var wantParent string
		var wantDepth int
		switch agentID {
		case childID:
			wantParent, wantDepth = parentID, 2
		case grandID:
			wantParent, wantDepth = childID, 3
		default:
			continue
		}
		if row.body["defenseclaw.agent.root.id"] != rootID ||
			row.body["defenseclaw.agent.parent.id"] != wantParent ||
			fmt.Sprint(row.body["defenseclaw.agent.depth"]) != fmt.Sprint(wantDepth) {
			t.Fatalf("event lost recursive ownership agent=%s event=%s body=%#v", agentID, row.eventName, row.body)
		}
		eventsByAgent[agentID] = append(eventsByAgent[agentID], row.eventName)
		switch row.eventName {
		case "subagent_start":
			starts[agentID]++
		case "subagent_stop":
			stops[agentID]++
			if fmt.Sprint(row.projected["outcome"]) != "completed" {
				t.Fatalf("terminal outcome agent=%s projected=%#v", agentID, row.projected)
			}
		case "tool_start", "tool_end":
			ownedTools[agentID+"\x00"+fmt.Sprint(row.body["gen_ai.tool.name"])] = true
		}
	}
	for _, agentID := range []string{childID, grandID} {
		if starts[agentID] != 1 || stops[agentID] != 1 {
			t.Fatalf("canonical child lifecycle agent=%s starts=%d stops=%d", agentID, starts[agentID], stops[agentID])
		}
		if len(eventsByAgent[agentID]) == 0 || eventsByAgent[agentID][0] != "subagent_start" {
			t.Fatalf("synthetic start was not emitted before first child event agent=%s events=%v", agentID, eventsByAgent[agentID])
		}
	}
	for _, key := range []string{
		childID + "\x00Bash", childID + "\x00collaboration.spawn_agent",
		grandID + "\x00Bash", grandID + "\x00collaboration.send_message",
	} {
		if !ownedTools[key] {
			t.Fatalf("missing tool ownership %q: %#v", key, ownedTools)
		}
	}

	database, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT event_name, projected_record_json FROM audit_events ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var projected strings.Builder
	modelResponses := 0
	for rows.Next() {
		var eventName, raw string
		if err := rows.Scan(&eventName, &raw); err != nil {
			t.Fatal(err)
		}
		projected.WriteString(raw)
		if eventName == observability.TelemetryEventModelResponse {
			modelResponses++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if modelResponses < 2 {
		t.Fatalf("subagent terminal responses=%d want at least 2", modelResponses)
	}
	for _, marker := range []string{message, childDone, grandDone} {
		if !strings.Contains(projected.String(), marker) {
			t.Fatalf("projected nested telemetry lost source message %q", marker)
		}
	}
}

func TestHookLifecycleV8PreservesRootDirectNestedFactsAndOmitsMissingData(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	bindHookLifecycleV8(t, api, fixture.runtime)

	metas := []llmEventMeta{
		{
			Source: "codex", Provider: "openai", Model: "gpt-5", SessionID: "session-root",
			RequestID: "request-root", RunID: "run-root", TurnID: "turn-root",
			AgentID: "agent-root", AgentName: "root", AgentType: "codex", RootAgentID: "agent-root",
			LineageProvenance: "reported", RootSessionID: "session-root", LifecycleID: "lifecycle-root",
			ExecutionID: "execution-root", LifecycleEvent: "session_start", LifecycleState: "active",
			LifecycleOutcome: "attempted", Phase: "session", OperationID: "operation-root", Sequence: 1,
		},
		{
			Source: "codex", SessionID: "session-child", AgentID: "agent-child", AgentName: "child",
			AgentType: "subagent", RootAgentID: "agent-root", ParentAgentID: "agent-root",
			LineageProvenance: "reported", RootSessionID: "session-root", ParentSessionID: "session-root",
			LifecycleID: "lifecycle-child", ExecutionID: "execution-child", LifecycleEvent: "subagent_start",
			LifecycleState: "active", LifecycleOutcome: "attempted", Phase: "session", PreviousPhase: "planning",
			OperationID: "operation-child", Sequence: 2, AgentDepth: 1, ReportedCost: true, ReportedCostUSD: 0.25,
		},
		{
			Source: "codex", SessionID: "session-grandchild", AgentID: "agent-grandchild", AgentName: "grandchild",
			AgentType: "subagent", RootAgentID: "agent-root", ParentAgentID: "agent-child",
			LineageProvenance: "reported", RootSessionID: "session-root", ParentSessionID: "session-child",
			LifecycleID: "lifecycle-grandchild", ExecutionID: "execution-grandchild", LifecycleEvent: "subagent_start",
			LifecycleState: "active", LifecycleOutcome: "attempted", Phase: "session",
			OperationID: "operation-grandchild", Sequence: 3, AgentDepth: 2,
		},
	}
	for _, meta := range metas {
		if got := api.emitHookLifecycleEvent(t.Context(), meta); got != hookLifecycleV8Persisted {
			t.Fatalf("agent %q emission=%d", meta.AgentID, got)
		}
	}
	rows := readStoredHookLifecycleV8(t, fixture.path)
	if len(rows) != 3 {
		t.Fatalf("rows=%d want 3", len(rows))
	}
	wants := []struct {
		agent, root, parent string
		depth               int
	}{
		{"agent-root", "agent-root", "", 0},
		{"agent-child", "agent-root", "agent-root", 1},
		{"agent-grandchild", "agent-root", "agent-child", 2},
	}
	for index, want := range wants {
		body := rows[index].body
		if body["gen_ai.agent.id"] != want.agent || body["defenseclaw.agent.root.id"] != want.root ||
			fmt.Sprint(body["defenseclaw.agent.depth"]) != fmt.Sprint(want.depth) {
			t.Errorf("row %d topology=%#v", index, body)
		}
		if want.parent == "" {
			if _, present := body["defenseclaw.agent.parent.id"]; present {
				t.Errorf("root fabricated parent: %#v", body)
			}
		} else if body["defenseclaw.agent.parent.id"] != want.parent {
			t.Errorf("row %d parent=%v want=%s", index, body["defenseclaw.agent.parent.id"], want.parent)
		}
	}
	if fmt.Sprint(rows[1].body["defenseclaw.agent.reported_cost.usd"]) != "0.25" {
		t.Fatalf("reported cost=%v", rows[1].body["defenseclaw.agent.reported_cost.usd"])
	}
	for _, key := range []string{
		"gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.usage.input_tokens",
		"gen_ai.usage.output_tokens", "defenseclaw.model.upstream_ms", "defenseclaw.tool.output_length",
		"defenseclaw.agent.phase.previous",
	} {
		if _, present := rows[0].body[key]; present {
			t.Errorf("unreported field %q was fabricated", key)
		}
	}
}

func hookLifecycleReloadPlan(
	t *testing.T, fixture sidecarRuntimeFixture, collect bool, sampler string,
) *config.ObservabilityV8Plan {
	t.Helper()
	local := fixture.plan.Snapshot().Local
	retentionDays := local.RetentionDays
	source := &config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: local.Path, JudgeBodiesPath: local.JudgeBodiesPath,
			RetentionDays: &retentionDays,
		},
		TracePolicy: config.ObservabilityV8TracePolicySource{Sampler: sampler},
	}
	if !collect {
		disabled := false
		source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketAgentLifecycle: {Collect: config.ObservabilityV8CollectSource{Logs: &disabled}},
			observability.BucketToolActivity:   {Collect: config.ObservabilityV8CollectSource{Logs: &disabled}},
		}
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func reloadHookLifecycleV8(t *testing.T, fixture sidecarRuntimeFixture, plan *config.ObservabilityV8Plan) {
	t.Helper()
	result, reloadErr := fixture.runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(plan, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload status=%s error=%v", result.Status(), reloadErr)
	}
}

func TestHookLifecycleV8LogsIgnoreTraceSamplingAndFollowReloadedCollection(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	bindHookLifecycleV8(t, api, fixture.runtime)

	reloadHookLifecycleV8(t, fixture, hookLifecycleReloadPlan(t, fixture, true, "always_off"))
	meta := hookLifecycleTestMeta("session_start")
	if got := api.emitHookLifecycleEvent(t.Context(), meta); got != hookLifecycleV8Persisted {
		t.Fatalf("always-off trace sampler suppressed log, emission=%d", got)
	}
	reloadHookLifecycleV8(t, fixture, hookLifecycleReloadPlan(t, fixture, false, "always_off"))
	meta = hookLifecycleTestMeta("turn_start")
	meta.OperationID = "operation-2"
	if got := api.emitHookLifecycleEvent(t.Context(), meta); got != hookLifecycleV8Dropped {
		t.Fatalf("disabled log collection emission=%d", got)
	}
	reloadHookLifecycleV8(t, fixture, hookLifecycleReloadPlan(t, fixture, true, "always_on"))
	meta = hookLifecycleTestMeta("turn_end")
	meta.OperationID = "operation-3"
	if got := api.emitHookLifecycleEvent(t.Context(), meta); got != hookLifecycleV8Persisted {
		t.Fatalf("re-enabled log collection emission=%d", got)
	}

	rows := readStoredHookLifecycleV8(t, fixture.path)
	if len(rows) != 2 || rows[0].generation != 2 || rows[1].generation != 4 {
		t.Fatalf("reload rows=%#v", rows)
	}
}

type failingHookLifecycleEmitter struct{}

func (*failingHookLifecycleEmitter) Emit(
	context.Context, router.Metadata, observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	return pipeline.LocalLogOutcome{}, errors.New("pre-admission failure")
}

func TestHookLifecycleV8FailureOwnershipNeverFallsBack(t *testing.T) {
	t.Run("bound runtime failure is terminal", func(t *testing.T) {
		api := &APIServer{}
		bindHookLifecycleV8(t, api, &failingHookLifecycleEmitter{})
		if got := api.emitHookLifecycleEvent(t.Context(), hookLifecycleTestMeta("session_start")); got != hookLifecycleV8Failed {
			t.Fatalf("emission=%d", got)
		}
	})

	t.Run("post-admission build failure persists nothing", func(t *testing.T) {
		fixture := newSidecarRuntimeFixture(t, true)
		api := &APIServer{}
		bindHookLifecycleV8(t, api, fixture.runtime)
		meta := hookLifecycleTestMeta("session_start")
		meta.Phase = "not a valid phase"
		if got := api.emitHookLifecycleEvent(t.Context(), meta); got != hookLifecycleV8Failed {
			t.Fatalf("emission=%d", got)
		}
		if rows := readStoredHookLifecycleV8(t, fixture.path); len(rows) != 0 {
			t.Fatalf("failed build persisted rows: %#v", rows)
		}
	})

	t.Run("unrepresentable required identity fails", func(t *testing.T) {
		fixture := newSidecarRuntimeFixture(t, true)
		api := &APIServer{}
		bindHookLifecycleV8(t, api, fixture.runtime)
		meta := hookLifecycleTestMeta("session_start")
		meta.SessionID = "session id with spaces"
		if got := api.emitHookLifecycleEvent(t.Context(), meta); got != hookLifecycleV8Failed {
			t.Fatalf("emission=%d", got)
		}
		if rows := readStoredHookLifecycleV8(t, fixture.path); len(rows) != 0 {
			t.Fatalf("unrepresentable occurrence persisted rows: %#v", rows)
		}
	})
}

func TestHookLifecycleOutcomeRetainsRawTerminalSemantics(t *testing.T) {
	tests := []struct {
		raw, event, state string
		payload           map[string]any
		want              string
	}{
		{"PermissionDenied", "tool_end", "active", nil, "denied"},
		{"PostToolUseFailure", "tool_end", "active", map[string]any{"error": "failed"}, "failed"},
		{"PostToolUse", "tool_end", "failed", nil, "failed"},
		{"SessionEnd", "session_end", "completed", map[string]any{"reason": "terminated"}, "terminated"},
		{"PostCompact", "compact_end", "active", map[string]any{"outcome": "no_change"}, "no_change"},
		{"PostCompact", "compact_end", "interrupted", nil, "cancelled"},
		{"PostCompact", "compact_end", "cancelled", nil, "cancelled"},
	}
	for _, test := range tests {
		if got := hookLifecycleOutcome(test.raw, test.event, test.state, test.payload); got != test.want {
			t.Errorf("%s outcome=%q want=%q", test.raw, got, test.want)
		}
	}
}

func TestHookLifecycleLineageProvenanceDistinguishesReportedAndInferred(t *testing.T) {
	root := hookLLMEventMeta(t.Context(), "codex", "session-root", "", "", "", "agent-root", "root", "codex", nil)
	root = applyHookEventMeta(root, "SessionStart", nil)
	if root.LineageProvenance != "inferred" {
		t.Fatalf("derived root/depth topology provenance=%q", root.LineageProvenance)
	}

	reportedPayload := map[string]any{
		"root_agent_id": "agent-root", "parent_agent_id": "agent-root", "agent_depth": float64(1),
	}
	reported := hookLLMEventMeta(
		t.Context(),
		"codex", "session-child", "", "", "", "agent-child", "child", "subagent", reportedPayload,
	)
	reported = applyHookEventMeta(reported, "SubagentStart", reportedPayload)
	if reported.LineageProvenance != "reported" {
		t.Fatalf("reported topology provenance=%q", reported.LineageProvenance)
	}

	inferred := hookLLMEventMeta(t.Context(), "codex", "session-child", "", "", "", "agent-child", "child", "subagent", nil)
	inferred = applyHookEventMeta(inferred, "SubagentStart", nil)
	if inferred.LineageProvenance != "inferred" || inferred.ParentAgentID == "" {
		t.Fatalf("inferred topology=%#v", inferred)
	}
}

var _ sidecarRuntimeEmitter = (*failingHookLifecycleEmitter)(nil)
