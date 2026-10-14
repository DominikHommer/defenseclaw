// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

func TestProtectedWriteApplyPatchProjectFiles(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	key := filepath.Join(home, ".ssh", "authorized_keys")
	project := filepath.Join(root, "project")
	sandboxProject := filepath.Join(root, "sandbox", "work", "proj")
	for _, dir := range []string{filepath.Dir(key), project, sandboxProject} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(key, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := "apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: codex.txt\n+codex-by-lane-S\n*** Update File: README.txt\n@@\n+codex-edit\n*** End Patch\nPATCH\n\necho r102-w-s-codex-benign"
	commandOnly := strings.Split(command, "\n\necho ")[0]
	absoluteProject := "apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: " + filepath.Join(project, "codex.txt") + "\n+x\n*** End Patch\nPATCH"
	protected := "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: " + key + "\n@@\n+marker\n*** End Patch\nPATCH"
	for _, row := range []struct {
		name, cwd, tool, connector, command string
		sandbox                             bool
		want                                string
	}{
		{"project Bash", project, "Bash", "claudecode", command, false, "allow"},
		{"project command", project, "exec_command", "codex", command, false, "allow"},
		{"project command only", project, "exec_command", "codex", commandOnly, false, "allow"},
		{"project shell command", project, "shell_command", "codex", commandOnly, false, "allow"},
		{"absolute project file", project, "exec_command", "codex", absoluteProject, false, "allow"},
		{"sandbox project Bash", sandboxProject, "Bash", "claudecode", command, true, "allow"},
		{"sandbox project command", sandboxProject, "exec_command", "codex", command, true, "allow"},
		{"sandbox protected path", sandboxProject, "exec_command", "codex", protected, true, "block"},
	} {
		t.Run(row.name, func(t *testing.T) {
			var inputArgs map[string]any
			if row.tool == "exec_command" {
				inputArgs = map[string]any{"cmd": row.command, "workdir": row.cwd, "yield_time_ms": 1000, "max_output_tokens": 1000}
			} else {
				inputArgs = map[string]any{"command": row.command}
			}
			args, err := json.Marshal(inputArgs)
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: row.tool, Args: args, CWD: row.cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
			findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
				Input: input, Connector: row.connector, EnforcementCapable: true,
				SkipLocalFilesystemResolution: row.sandbox,
			})
			if got := string(buildVerdict(findings, "tool_call").Action); got != row.want {
				t.Fatalf("decision = %s, want %s", got, row.want)
			}
		})
	}
}

func TestProtectedWriteApplyPatchCopyProject(t *testing.T) {
	command := "apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: codex.txt\n+codex-by-lane-S\n*** Update File: README.txt\n@@\n+codex-edit\n*** End Patch\nPATCH\n\necho r102-w-s-codex-benign"
	binding := sandboxTestBinding("codex")
	ctx := withAuthenticatedHookConnector(
		sandboxauth.WithRequest(t.Context(), binding, sandboxauth.NewFSView(binding, nil)), "codex",
	)
	cwd := hookCWDForContext(ctx, "/sandbox/work/proj")
	toolInput := map[string]any{
		"cmd": command, "workdir": "/sandbox/work/proj", "yield_time_ms": 1000, "max_output_tokens": 1000,
	}
	args, err := json.Marshal(toolInput)
	if err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: "exec_command", Args: args, CWD: cwd, ActiveHome: sandboxauth.SandboxHome, DialectHint: actionfacts.DialectPOSIX}
	findings := dispatchTrustedAction(ctx, trustedActionRequest{
		Input: input, Connector: "codex", EnforcementCapable: true, SkipLocalFilesystemResolution: true,
	})
	if got := string(buildVerdict(findings, "tool_call").Action); got != "allow" {
		t.Fatalf("copy project decision = %s, want allow", got)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	response := api.evaluateCodexHook(ctx, codexHookRequest{
		HookEventName: "PreToolUse", ToolName: "exec_command", ToolInput: toolInput, CWD: cwd,
	})
	if response.Action != "allow" {
		t.Fatalf("copy project hook = %s, want allow", response.Action)
	}
	body, err := json.Marshal(map[string]any{
		"session_id": "patch-copy-project", "hook_event_name": "PreToolUse", "tool_name": "exec_command",
		"cwd": "/sandbox/work/proj", "tool_input": toolInput,
	})
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", bytes.NewReader(body)).WithContext(ctx)
	setTestCodexHookBinding(httpRequest, "PreToolUse", defaultTestCodexHookContract)
	httpResponse := httptest.NewRecorder()
	api.handleAgentHook("codex").ServeHTTP(httpResponse, httpRequest)
	var verdict struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(httpResponse.Body.Bytes(), &verdict); err != nil {
		t.Fatalf("hook response: HTTP %d: %v", httpResponse.Code, err)
	}
	if verdict.Action != "allow" {
		t.Fatalf("copy project request = %s, want allow", verdict.Action)
	}
}
