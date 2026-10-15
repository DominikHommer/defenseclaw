// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The sandbox ingress fixture and the Hermes helpers are POSIX-only; the
// reduction itself is platform-neutral and is pinned on every OS by the
// actionfacts over-limit tests.

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// overLimitWriteText is written text over the 256 KiB argument limit.
var overLimitWriteText = strings.Repeat("# k\n", 70000)

// overLimitNativeWriteCalls are native file-write tool calls whose
// arguments are over the argument limit, in each harness's shape.
func overLimitNativeWriteCalls() []nativeWriteCall {
	return []nativeWriteCall{
		{"claudecode", "Write", func(p string) map[string]any { return map[string]any{"file_path": p, "content": overLimitWriteText} }},
		{"claudecode", "Write", func(p string) map[string]any {
			return map[string]any{"file_path": p, "content": overLimitWriteText[:100<<10]}
		}},
		{"claudecode", "Edit", func(p string) map[string]any {
			return map[string]any{"file_path": p, "old_string": "# base", "new_string": overLimitWriteText}
		}},
		{"claudecode", "MultiEdit", func(p string) map[string]any {
			return map[string]any{"file_path": p, "edits": []any{map[string]any{"old_string": "# base", "new_string": overLimitWriteText}}}
		}},
		{"opencode", "write", func(p string) map[string]any { return map[string]any{"filePath": p, "content": overLimitWriteText} }},
		{"opencode", "edit", func(p string) map[string]any {
			return map[string]any{"filePath": p, "oldString": "# base", "newString": overLimitWriteText}
		}},
		{"codex", "apply_patch", func(p string) map[string]any {
			return map[string]any{"command": "*** Begin Patch\n*** Update File: " + p + "\n@@\n # base\n" +
				strings.Repeat("+# k\n", 70000) + "*** End Patch\n"}
		}},
		{"copilot", "create", func(p string) map[string]any { return map[string]any{"path": p, "file_text": overLimitWriteText} }},
	}
}

// overLimitHermesCalls are Hermes write_file and patch (replace) calls over
// the argument limit.
func overLimitHermesCalls() []hermesPatchCall {
	return []hermesPatchCall{
		{"write-file", "write_file", func(p string) map[string]any { return map[string]any{"path": p, "content": overLimitWriteText} }},
		{"replace", "patch", func(p string) map[string]any {
			return map[string]any{"path": p, "old_string": "# base", "new_string": overLimitWriteText}
		}},
	}
}

func overLimitHostHook(t *testing.T, connector, home, body string) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(body)))
	switch connector {
	case "codex":
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	case "copilot":
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
	}
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	return recorder.Body.String()
}

// TestOverLimitNativeWritesOfAuthorizedKeysAreBlockedOnTheHost pins that a
// native file-write tool call naming ~/.ssh/authorized_keys is blocked by
// the SSH persistence rule when its arguments are over the argument limit,
// and that the same call writing a project file stays allowed. The
// limit-exceeded arguments named no write target, so the call was allowed
// with no rule (GAP-0674).
func TestOverLimitNativeWritesOfAuthorizedKeysAreBlockedOnTheHost(t *testing.T) {
	home, project := hermesPatchHome(t)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	targets := map[string]bool{keys: true, filepath.Join(project, "big.json"): false}
	for i, call := range overLimitNativeWriteCalls() {
		for target, want := range targets {
			t.Run(fmt.Sprintf("%s/block=%t", call.name(i), want), func(t *testing.T) {
				got := overLimitHostHook(t, call.connector, home, call.body(t, project, target))
				if blocked := nativeWriteBlocked(t, got); blocked != want {
					t.Fatalf("blocked = %t, want %t: %.600s", blocked, want, got)
				}
			})
		}
	}
	for _, call := range overLimitHermesCalls() {
		for target, want := range targets {
			t.Run(fmt.Sprintf("hermes-%s/block=%t", call.name, want), func(t *testing.T) {
				got := hermesPatchHostHook(t, home, project, hermesPatchBody(t, project, call.tool, call.args(target)))
				if blocked := hermesPatchVerdict(t, got); blocked != want {
					t.Fatalf("blocked = %t, want %t: %.600s", blocked, want, got)
				}
			})
		}
	}
}

// TestOverLimitNativeWritesOfAuthorizedKeysAreBlockedInASandbox is the same
// table through the authenticated sandbox ingress, with the guest home.
func TestOverLimitNativeWritesOfAuthorizedKeysAreBlockedInASandbox(t *testing.T) {
	f := newSandboxIngressFixture(t)
	versions := map[string][3]string{
		"opencode":   {"1.18.10", "opencode-hooks-v1", "/api/v1/opencode/hook"},
		"claudecode": {"2.1.156", "claudecode-hooks-v1", "/api/v1/claude-code/hook"},
		"codex":      {"0.128.0", "codex-hooks-v1", "/api/v1/codex/hook"},
		"copilot":    {"1.0.40", "copilot-hooks-v1", "/api/v1/copilot/hook"},
	}
	keys := sandboxauth.SandboxHome + "/.ssh/authorized_keys"
	targets := map[string]bool{keys: true, "/work/app/big.json": false}
	for i, call := range overLimitNativeWriteCalls() {
		v := versions[call.connector]
		var headers []string
		switch call.connector {
		case "codex":
			headers = []string{"X-DefenseClaw-Hook-Event", "PreToolUse", "X-DefenseClaw-Hook-Contract", v[1]}
		case "copilot":
			headers = []string{"X-DefenseClaw-Copilot-Event", "preToolUse"}
		}
		for target, want := range targets {
			t.Run(fmt.Sprintf("%s/block=%t", call.name(i), want), func(t *testing.T) {
				_, token := f.mint(t, fmt.Sprintf("dc-ol-%s-%t", call.name(i), want), call.connector, v[0], v[1], f.project)
				resp := f.hook(t, v[2], token, call.body(t, "/work/app", target), headers...)
				raw, _ := json.Marshal(resp)
				if got := nativeWriteBlocked(t, string(raw)); got != want {
					t.Fatalf("blocked = %t, want %t: %.600s", got, want, raw)
				}
			})
		}
	}
	for _, call := range overLimitHermesCalls() {
		for target, want := range targets {
			t.Run(fmt.Sprintf("hermes-%s/block=%t", call.name, want), func(t *testing.T) {
				_, token := f.mint(t, fmt.Sprintf("dc-ol-hermes-%s-%t", call.name, want), "hermes", "0.19.0", "hermes-hooks-v1", f.project)
				resp := f.hook(t, "/api/v1/hermes/hook", token, hermesPatchBody(t, "/work/app", call.tool, call.args(target)))
				raw, _ := json.Marshal(resp)
				if got := hermesPatchVerdict(t, string(raw)); got != want {
					t.Fatalf("blocked = %t, want %t: %.600s", got, want, raw)
				}
			})
		}
	}
}

// TestOverLimitWriteToolCallsWithUnreadableTargets pins the conservative
// block of an over-limit write tool call whose targets cannot be read, with
// its reason, and that an over-limit call of a tool that writes no file
// keeps the limit-exceeded result (allowed).
func TestOverLimitWriteToolCallsWithUnreadableTargets(t *testing.T) {
	home, project := hermesPatchHome(t)
	body := func(tool string, args map[string]any) string {
		return string(mustJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-ol-" + tool, "turn_id": "t1",
			"cwd": project, "tool_name": tool, "tool_input": args, "tool_use_id": "u1"}))
	}
	big := filepath.Join(project, "big.json")
	for name, args := range map[string]map[string]any{
		"unknown key":       {"file_path": big, "content": overLimitWriteText, "mode": "x"},
		"large unknown key": {"file_path": big, "notes": overLimitWriteText},
		"content not text":  {"file_path": big, "content": []any{overLimitWriteText}},
	} {
		t.Run(name, func(t *testing.T) {
			got := overLimitHostHook(t, "claudecode", home, body("Write", args))
			if !nativeWriteBlocked(t, got) || !strings.Contains(got, "too large or malformed") {
				t.Fatalf("verdict = %.600s", got)
			}
		})
	}
	for name, call := range map[string][2]any{
		"grep": {"Grep", map[string]any{"pattern": overLimitWriteText, "path": project}},
		"read": {"Read", map[string]any{"file_path": big, "pages": overLimitWriteText}},
	} {
		t.Run(name, func(t *testing.T) {
			got := overLimitHostHook(t, "claudecode", home, body(call[0].(string), call[1].(map[string]any)))
			if nativeWriteBlocked(t, got) {
				t.Fatalf("blocked: %.600s", got)
			}
		})
	}
}
