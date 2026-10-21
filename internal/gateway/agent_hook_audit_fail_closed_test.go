// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// failingAuditEmitter fails every audit write of the logger once fail is set,
// with the error a store returns after its busy timeout and retries.
type failingAuditEmitter struct {
	audit.RuntimeV8Emitter
	fail bool
}

func (emitter *failingAuditEmitter) EmitRuntimeV8(
	ctx context.Context,
	metadata router.Metadata,
	builder audit.RuntimeV8Builder,
) (audit.RuntimeV8EmitOutcome, error) {
	if emitter.fail {
		return audit.RuntimeV8EmitOutcome{}, errors.New("audit: persist runtime record: database is locked (5) (SQLITE_BUSY)")
	}
	return emitter.RuntimeV8Emitter.EmitRuntimeV8(ctx, metadata, builder)
}

type auditFailureHookFixture struct {
	api     *APIServer
	path    string
	emitter *failingAuditEmitter
}

func newAuditFailureHookFixture(t *testing.T, failMode string) auditFailureHookFixture {
	t.Helper()
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	emitter := &failingAuditEmitter{RuntimeV8Emitter: &sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints}}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(emitter)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.HookFailMode = failMode
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	return auditFailureHookFixture{api: api, path: fixture.path, emitter: emitter}
}

func (fixture auditFailureHookFixture) preToolUse(t *testing.T, toolUseID string) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "s-audit-" + toolUseID, "cwd": t.TempDir(),
		"tool_name": "Bash", "tool_use_id": toolUseID, "tool_input": map[string]any{"command": "echo ok"},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	fixture.api.handleAgentHook("claudecode").ServeHTTP(recorder,
		httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// lastHookDecisionAction is the action of the newest hook_decision record.
func lastHookDecisionAction(t *testing.T, path string) string {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var raw string
	if err := database.QueryRow(`SELECT projected_record_json FROM audit_events WHERE event_name = 'hook_decision' ORDER BY rowid DESC LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var record struct {
		Body map[string]any `json:"body"`
	}
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"defenseclaw.guardrail.effective_action"} {
		if action, ok := record.Body[key].(string); ok {
			return action
		}
	}
	return raw
}

// Review of G-flood-wal (P1): an accepted hook whose audit row could not be
// written answered with its computed allow, so a call ran with no durable
// record. Outside Secure Client the fail mode is closed: the call is denied,
// and the exported hook_decision says so.
func TestHookAuditWriteFailureDeniesTheCall(t *testing.T) {
	t.Run("store refuses the row (disk full)", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "")
		if got := fixture.preToolUse(t, "toolu-before")["action"]; got != "allow" {
			t.Fatalf("healthy store: action %v, want allow", got)
		}
		database, err := sql.Open("sqlite", fixture.path)
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		if _, err := database.Exec(`CREATE TRIGGER zz_audit_disk_full BEFORE INSERT ON audit_events
			WHEN NEW.action = 'connector-hook' BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
			t.Fatal(err)
		}
		out := fixture.preToolUse(t, "toolu-full")
		reason, _ := out["reason"].(string)
		if out["action"] != "block" || !strings.Contains(reason, "could not write the call's audit record") {
			t.Fatalf("full store: action %v reason %q, want a fail-closed block", out["action"], reason)
		}
		if got := lastHookDecisionAction(t, fixture.path); got != "block" {
			t.Fatalf("hook_decision action %q, want block", got)
		}
	})
	t.Run("store stays busy", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "")
		fixture.emitter.fail = true
		if out := fixture.preToolUse(t, "toolu-busy"); out["action"] != "block" {
			t.Fatalf("busy store: action %v, want block", out["action"])
		}
	})
	t.Run("explicit open keeps the verdict", func(t *testing.T) {
		fixture := newAuditFailureHookFixture(t, "open")
		fixture.emitter.fail = true
		if out := fixture.preToolUse(t, "toolu-open"); out["action"] != "allow" {
			t.Fatalf("open fail mode: action %v, want allow", out["action"])
		}
	})
}

// A failed audit write keeps a block, a session-ending event and an event the
// agent cannot block; only an exact replay is not audited at all.
func TestHookAuditFailureResponseKeepsWhatItCannotTighten(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "")
	fixture.emitter.fail = true
	api := fixture.api
	allow := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action", EvaluationID: "eval-1"}
	finalize := func(req agentHookRequest, resp agentHookResponse) hookFinalizationResult {
		t.Helper()
		req.ConnectorName = "claudecode"
		return api.finalizeAgentHook(t.Context(), "claudecode", req, resp, nil, []byte(`{}`), time.Millisecond, false, nil)
	}
	denied := finalize(agentHookRequest{HookEventName: "PreToolUse", SessionID: "s-1", ToolName: "Bash",
		Payload: map[string]interface{}{"tool_name": "Bash"}}, allow)
	if !denied.AuditFailedClosed || denied.Response.Action != "block" || !denied.Enforced || denied.AuditPersisted ||
		denied.Response.EvaluationID != "eval-1" {
		t.Fatalf("PreToolUse allow with a failed audit write: %+v", denied)
	}
	block := agentHookResponse{Action: "block", RawAction: "block", Mode: "action", Reason: "policy"}
	if kept := finalize(agentHookRequest{HookEventName: "PreToolUse", SessionID: "s-1", ToolName: "Bash"}, block); kept.AuditFailedClosed || kept.Response.Reason != "policy" {
		t.Fatalf("a block was replaced: %+v", kept)
	}
	if kept := finalize(agentHookRequest{HookEventName: "Stop", SessionID: "s-1"}, allow); kept.AuditFailedClosed || kept.Response.Action != "allow" {
		t.Fatalf("a Stop was denied: %+v", kept)
	}
	if kept := finalize(agentHookRequest{HookEventName: "PostToolUse", SessionID: "s-1", ToolName: "Bash"}, allow); kept.AuditFailedClosed {
		t.Fatalf("a PostToolUse was denied: %+v", kept)
	}
	if replay := finalize(agentHookRequest{HookEventName: "PreToolUse", SessionID: "s-1", SuppressCorrelationEmit: true}, allow); replay.AuditFailedClosed || replay.Response.Action != "allow" {
		t.Fatalf("an exact replay was denied: %+v", replay)
	}
}
