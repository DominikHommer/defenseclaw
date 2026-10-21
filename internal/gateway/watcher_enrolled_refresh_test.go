// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0216: a managed Windows gateway knew an enrolled user's MCP servers
// only from the record the hook enumerator publishes every 30 seconds, so a
// server changed under the same name was decided on its old definition and
// old verdict, and its call answered before any scan. Before an MCP tool
// call of a published connector is decided, the enumerator publishes the
// users' servers again and the gateway reads them; a refresh that fails is
// returned, so the call is refused.
func TestEnrolledMCPServersAreReadAgainBeforeAToolCall(t *testing.T) {
	ctx := context.Background()
	var s Sidecar
	if err := s.refreshEnrolledMCPBeforeCall(ctx, "claudecode"); err != nil {
		t.Fatalf("a gateway without enrolled users refreshed: %v", err)
	}
	var steps []string
	failing := false
	s.enrolledMCPRefresh.Store(&enrolledMCPRefresher{
		refresh: func(context.Context) error {
			steps = append(steps, "publish")
			if failing {
				return errors.New("the hook enumerator service is not serving")
			}
			return nil
		},
		reload: func() { steps = append(steps, "read") },
	})
	if err := s.refreshEnrolledMCPBeforeCall(ctx, "claudecode"); err != nil || !reflect.DeepEqual(steps, []string{"publish", "read"}) {
		t.Fatalf("refresh = %v, steps %v; want the servers published, then read", err, steps)
	}
	steps = nil
	if err := s.refreshEnrolledMCPBeforeCall(ctx, "codex"); err != nil || len(steps) != 0 {
		t.Fatalf("a connector the enumerator does not publish refreshed: %v %v", err, steps)
	}
	failing = true
	if err := s.refreshEnrolledMCPBeforeCall(ctx, "kiro"); err == nil || !reflect.DeepEqual(steps, []string{"publish"}) {
		t.Fatalf("failed refresh = %v, steps %v; want the error and no read of a stale record", err, steps)
	}
}

// The hook reads the users' servers again before its unreadable-state and
// pending checks, so a changed definition is pending at the first call; a
// refresh that fails refuses the call; a tool result and Secure Client do not
// refresh.
func TestHookDecidesMCPToolCallOnTheRefreshedDefinition(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}
	refreshed, refreshErr := 0, error(nil)
	api.SetMCPRefreshBeforeCall(func(_ context.Context, connector string) error {
		if connector != "claudecode" {
			t.Errorf("refreshed for %q", connector)
		}
		refreshed++
		return refreshErr
	})
	// Before the refresh the gateway still holds the old, admitted
	// definition; the refreshed list holds the changed one.
	api.SetMCPAdmissionPending(func(_, server, _, _ string) (string, bool) { return server, refreshed > 0 })
	call := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__gb05-benign__ping",
		ToolInput: map[string]interface{}{}, CWD: `C:\Users\dcw-std1\r103-gb05-proj`}
	if resp := api.evaluateClaudeCodeHook(context.Background(), call); resp.Action != "block" || refreshed != 1 {
		t.Fatalf("changed server: action=%q after %d refreshes, want block after one", resp.Action, refreshed)
	}

	api.SetMCPAdmissionPending(func(_, server, _, _ string) (string, bool) { return server, false })
	refreshErr = errors.New("the hook enumerator did not answer")
	if resp := api.evaluateClaudeCodeHook(context.Background(), call); resp.Action != "block" {
		t.Fatalf("failed refresh: action=%q, want the call refused", resp.Action)
	}
	refreshErr = nil
	if resp := api.evaluateClaudeCodeHook(context.Background(), call); resp.Action == "block" {
		t.Fatalf("current, admitted server: action=%q, want it allowed", resp.Action)
	}

	result := call
	result.HookEventName = "PostToolUse"
	before := refreshed
	api.evaluateClaudeCodeHook(context.Background(), result)
	if refreshed != before {
		t.Fatal("a tool result refreshed the servers")
	}

	sc := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	sc.Guardrail.Mode = "action"
	sc.Guardrail.Connector = "claudecode"
	sc.DeploymentMode = "managed_enterprise"
	if !sc.SecureClientIntegration() {
		t.Fatal("fixture is not a Secure Client configuration")
	}
	scAPI := &APIServer{scannerCfg: sc}
	scAPI.SetMCPRefreshBeforeCall(func(context.Context, string) error { t.Error("Secure Client refreshed"); return nil })
	if _, refused := scAPI.mcpDefinitionRefreshDecision(context.Background(), "claudecode", "PreToolUse",
		mcpRuntimeProbe{ServerName: "gb05-benign", ToolName: "mcp__gb05-benign__ping", Surface: "hook", Matched: true}); refused {
		t.Fatal("Secure Client refused a call on a refresh")
	}
}

// GAP-0216 (T10b, TST-2275): with the hook enumerator stopped, the refresh
// before a tool call waited its 10 second bound, past the 3.5 seconds the
// hook waits, so the agent got the hook's no-answer failure instead of the
// wait. A refresh that does not finish within its budget refuses the call
// as not scanned yet, inside the hook's wait, and the list read before the
// refresh is neither replaced nor used to allow the call.
func TestSlowRefreshRefusesTheCallInsideTheHookWait(t *testing.T) {
	saved := enrolledMCPRefreshBudget
	enrolledMCPRefreshBudget = 200 * time.Millisecond
	t.Cleanup(func() { enrolledMCPRefreshBudget = saved })

	var s Sidecar
	release := make(chan struct{})
	var reads int
	s.enrolledMCPRefresh.Store(&enrolledMCPRefresher{
		// The enumerator never answers: the refresh ends only with ctx.
		refresh: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return nil
			}
		},
		reload: func() { reads++ },
	})
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}
	api.SetMCPRefreshBeforeCall(s.refreshEnrolledMCPBeforeCall)
	// The list read before the refresh holds the old, admitted definition.
	api.SetMCPAdmissionPending(func(_, server, _, _ string) (string, bool) { return server, false })
	call := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__gb05-benign__ping",
		ToolInput: map[string]interface{}{}, CWD: `C:\Users\dcw-std1\r103-gb05-proj`}
	const wait = "DefenseClaw is still scanning MCP server gb05-benign"

	started := time.Now()
	resp := api.evaluateClaudeCodeHook(context.Background(), call)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the slow refresh held the call %s, want it answered inside the hook's 3.5 s wait", elapsed)
	}
	if resp.Action != "block" || !strings.Contains(resp.Reason, wait) {
		t.Fatalf("slow refresh: action=%q reason=%q, want the call refused with the wait", resp.Action, resp.Reason)
	}
	if reads != 0 {
		t.Fatal("a refresh that did not finish replaced the list")
	}

	// A call that arrives while another call's refresh still runs waits only
	// its own budget, not the other refresh plus its own.
	first := make(chan claudeCodeHookResponse, 1)
	go func() { first <- api.evaluateClaudeCodeHook(context.Background(), call) }()
	time.Sleep(100 * time.Millisecond)
	started = time.Now()
	second := api.evaluateClaudeCodeHook(context.Background(), call)
	if elapsed := time.Since(started); elapsed > enrolledMCPRefreshBudget+time.Second {
		t.Fatalf("the waiting call took %s, want at most its own budget", elapsed)
	}
	if second.Action != "block" || !strings.Contains(second.Reason, wait) {
		t.Fatalf("waiting call: action=%q reason=%q, want the wait", second.Action, second.Reason)
	}
	if got := <-first; got.Action != "block" {
		t.Fatalf("first call: action=%q, want block", got.Action)
	}

	// Once the enumerator answers in time, the call is decided on the
	// refreshed list.
	close(release)
	if resp := api.evaluateClaudeCodeHook(context.Background(), call); resp.Action == "block" || reads != 1 {
		t.Fatalf("answered refresh: action=%q after %d reads, want allowed after one", resp.Action, reads)
	}
}

// The refresh keeps a margin before the deadline of a request that has
// one, and otherwise gets its whole budget.
func TestRefreshDeadlineKeepsAMarginBeforeTheRequestDeadline(t *testing.T) {
	now := time.Now()
	if got := enrolledMCPRefreshDeadline(context.Background(), now); !got.Equal(now.Add(enrolledMCPRefreshBudget)) {
		t.Fatalf("no request deadline: %s, want the budget", got.Sub(now))
	}
	soon, cancel := context.WithDeadline(context.Background(), now.Add(time.Second))
	defer cancel()
	if got := enrolledMCPRefreshDeadline(soon, now); !got.Equal(now.Add(time.Second - enrolledMCPRefreshMargin)) {
		t.Fatalf("request ends in 1 s: %s, want 1 s minus the margin", got.Sub(now))
	}
	late, cancelLate := context.WithDeadline(context.Background(), now.Add(time.Minute))
	defer cancelLate()
	if got := enrolledMCPRefreshDeadline(late, now); !got.Equal(now.Add(enrolledMCPRefreshBudget)) {
		t.Fatalf("request ends in 1 min: %s, want the budget", got.Sub(now))
	}
}
