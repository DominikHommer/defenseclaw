// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A managed gateway cannot look into the user's home (ProtectHome; the
// mode-zero parent stands in for it), so a symlink there to authorized_keys
// is known only from the write evidence of the hook running as the user.
// That evidence must describe the Copilot call the gateway judges: a decoy
// tool_name or tool_input beside the camelCase toolName and toolArgs, a
// toolArgs JSON string, or a VS Code Local tool name. Each write to the link
// blocks; an ordinary file the evidence lists stays allowed.
func TestManagedCopilotWriteThroughHomeSymlinkUsesTheJudgedCall(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "alice")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	notes := filepath.Join(project, "notes.txt")
	for _, file := range []string{keys, notes} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(project, "deploy.cfg")
	if err := os.Symlink(keys, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	patch := func(path string) string {
		return "*** Begin Patch\n*** Update File: " + path + "\n@@\n # base\n+ssh-ed25519 AAAA marker\n*** End Patch\n"
	}
	jsonText := func(v any) string { return string(mustJSON(t, v)) }
	for _, row := range []struct {
		name  string
		body  map[string]any
		block bool
	}{
		{"apply_patch with a decoy tool_name", map[string]any{"toolName": "apply_patch", "tool_name": "read_file",
			"toolArgs": patch(link)}, true},
		{"apply_patch JSON string with a decoy tool_name", map[string]any{"toolName": "apply_patch", "tool_name": "view",
			"toolArgs": jsonText(patch(link))}, true},
		{"shell toolArgs JSON string", map[string]any{"toolName": "bash",
			"toolArgs": jsonText(map[string]any{"command": "echo marker >> deploy.cfg", "description": "x"})}, true},
		{"shell toolArgs with a decoy tool_input", map[string]any{"toolName": "bash",
			"toolArgs":   map[string]any{"command": "echo marker >> deploy.cfg"},
			"tool_input": map[string]any{"command": "true"}}, true},
		{"VS Code Local tool in a CLI body", map[string]any{"toolName": "create_file",
			"toolArgs": jsonText(map[string]any{"filePath": link, "content": "ssh-ed25519 AAAA marker\n"})}, true},
		{"apply_patch of an ordinary file with a decoy tool_name", map[string]any{"toolName": "apply_patch",
			"tool_name": "read_file", "toolArgs": patch(notes)}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
			row.body["sessionId"] = "s-" + strings.ReplaceAll(row.name, " ", "-")
			row.body["timestamp"] = 1790483549431
			row.body["cwd"] = project
			body := mustJSON(t, row.body)
			header := hookpaths.ResolveConnector("copilot", body)
			if err := os.Chmod(homes, 0); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
			req.Header.Set(hookpaths.Header, header)
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			recorder := httptest.NewRecorder()
			api.handleAgentHook("copilot").ServeHTTP(recorder, req)
			var verdict map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &verdict); err != nil {
				t.Fatalf("verdict %q: %v", recorder.Body.String(), err)
			}
			want := "allow"
			if row.block {
				want = "block"
			}
			if verdict["action"] != want {
				t.Fatalf("action = %v, want %s: %.800s", verdict["action"], want, recorder.Body.String())
			}
		})
	}
}
