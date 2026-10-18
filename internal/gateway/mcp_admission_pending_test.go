// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0112: a project MCP server Claude Code started before the install
// watcher admitted it answered its first tool calls, a decoy a scan rejects
// included. The hook refuses a call of a server whose admission is pending
// (fail closed) and leaves results and other servers as they were.
func TestHookRefusesMCPToolOfServerWithoutAdmission(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}
	type ask struct{ connector, server, cwd string }
	var asked []ask
	api.SetMCPAdmissionPending(func(connector, server, _ /*home*/, cwd string) (string, bool) {
		asked = append(asked, ask{connector, server, cwd})
		return server, server == "gb05-decoy"
	})

	call := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__gb05-decoy__ping",
		ToolInput: map[string]interface{}{}, CWD: "/work/decoy"}
	if resp := api.evaluateClaudeCodeHook(context.Background(), call); resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("pending server: action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if len(asked) == 0 || asked[0] != (ask{"claudecode", "gb05-decoy", "/work/decoy"}) {
		t.Fatalf("asked %+v, want the decoy of claudecode in its project", asked)
	}
	admitted := call
	admitted.ToolName = "mcp__gb05-benign__ping"
	if resp := api.evaluateClaudeCodeHook(context.Background(), admitted); resp.Action == "block" {
		t.Fatalf("admitted server: action=%q, want it allowed", resp.Action)
	}
	result := call
	result.HookEventName = "PostToolUse"
	asked = nil
	api.evaluateClaudeCodeHook(context.Background(), result)
	if len(asked) != 0 {
		t.Fatalf("a tool result asked about admission: %+v", asked)
	}

	codexCfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	codexCfg.Guardrail.Mode = "action"
	codexCfg.Guardrail.Connector = "codex"
	codex := &APIServer{scannerCfg: codexCfg}
	codex.SetMCPAdmissionPending(func(connector, server, _, _ string) (string, bool) {
		return server, connector == "codex" && server == "gb05-decoy"
	})
	resp := codex.evaluateCodexHook(context.Background(), codexHookRequest{HookEventName: "PreToolUse",
		ToolName: "mcp__gb05-decoy__ping", ToolInput: map[string]interface{}{}, CWD: "/work/decoy"})
	if resp.Action != "block" {
		t.Fatalf("codex pending server: action=%q, want block", resp.Action)
	}
}

// Secure Client keeps the hook of main (issue #1092).
func TestHookAdmissionPendingIsNotCheckedOnSecureClient(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.DeploymentMode = "managed_enterprise"
	if !cfg.SecureClientIntegration() {
		t.Fatal("fixture is not a Secure Client configuration")
	}
	api := &APIServer{scannerCfg: cfg}
	called := false
	api.SetMCPAdmissionPending(func(_, server, _, _ string) (string, bool) { called = true; return server, true })
	if _, refused := api.mcpAdmissionPendingDecision(context.Background(), "claudecode", "PreToolUse",
		mcpRuntimeProbe{ServerName: "gb05-decoy", ToolName: "mcp__gb05-decoy__ping", Surface: "hook", Matched: true}); refused || called {
		t.Fatalf("refused=%v called=%v on Secure Client, want neither", refused, called)
	}
}

// GAP-0210: the refusal of a call whose server admission is pending reaches
// the agent as a wait with retry guidance, not as the redacted registry
// fields of the decision ("registry_status=unknown registry_configured=false")
// or the final "Do not retry" block sentence. Standalone enterprise reads the
// same sentence.
func TestHookAdmissionPendingTellsTheAgentWhenToRetry(t *testing.T) {
	t.Cleanup(func() { setStandaloneEnterpriseActive(false) })
	for _, standalone := range []bool{false, true} {
		setStandaloneEnterpriseActive(standalone)
		cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "claudecode"
		api := &APIServer{scannerCfg: cfg}
		api.SetMCPAdmissionPending(func(_, server, _, _ string) (string, bool) { return server, true })
		resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{HookEventName: "PreToolUse",
			ToolName: "mcp__gb05-decoy__ping", ToolInput: map[string]interface{}{}, CWD: "/work/decoy"})
		if resp.Action != "block" {
			t.Fatalf("standalone=%v: action=%q, want block", standalone, resp.Action)
		}
		want := "DefenseClaw is still scanning MCP server gb05-decoy, so its tools are blocked until the scan finishes. " +
			"Try the same call again in about a minute. If the scan rejects the server, its calls stay blocked."
		if resp.Reason != want {
			t.Errorf("standalone=%v: reason %q, want %q", standalone, resp.Reason, want)
		}
		for _, leaked := range []string{"registry_status", "registry_configured", "Do not retry", "redacted"} {
			if strings.Contains(resp.Reason, leaked) {
				t.Errorf("standalone=%v: reason %q carries %q", standalone, resp.Reason, leaked)
			}
		}
	}
	// The OS notification names the state too.
	source := assetPolicyResponseReason(runtimeAssetDisableBlockDecision("mcp", "gb05-decoy", "claudecode", "hook", "x", "mcp-admission-pending"))
	if got := agentAssetPolicySubject(source); got != "MCP server gb05-decoy is not scanned yet; try the call again in about a minute" {
		t.Errorf("subject %q", got)
	}
	// Another source keeps its own wording.
	if got := agentMCPAdmissionPendingSentence(strings.Replace(source, "mcp-admission-pending", "runtime-disable", 2)); got != "" {
		t.Errorf("a runtime disable read as pending: %q", got)
	}
}
