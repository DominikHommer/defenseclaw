// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
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
