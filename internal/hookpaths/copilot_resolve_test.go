// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A Copilot body is resolved as the gateway's Copilot profiles read it
// (copilotargs): the camelCase spellings first, a freeform apply_patch, a
// toolArgs JSON string and a VS Code Local tool. A body that spells the tool
// name or the arguments twice with different values gets the map of the
// spelling the gateway reads, marked incomplete, for every connector.
func TestResolveConnectorReadsTheGatewayProjection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the managed hook sends write evidence on Linux and macOS only")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(project, "notes.txt")
	if err := os.WriteFile(target, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	patch := "*** Begin Patch\n*** Update File: " + target + "\n@@\n-a\n+b\n*** End Patch\n"
	jsonText := func(v any) string {
		encoded, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	shell := map[string]any{"command": "echo b >> notes.txt"}
	for _, row := range []struct {
		name, connector   string
		body              map[string]any
		listed, truncated bool
	}{
		{"cli apply_patch text", "copilot", map[string]any{"toolName": "apply_patch", "toolArgs": patch}, true, false},
		{"cli apply_patch JSON string", "copilot", map[string]any{"toolName": "apply_patch", "toolArgs": jsonText(patch)}, true, false},
		{"cli shell toolArgs JSON string", "copilot", map[string]any{"toolName": "bash", "toolArgs": jsonText(shell)}, true, false},
		{"cli shell toolArgs object", "copilot", map[string]any{"toolName": "bash", "toolArgs": shell}, true, false},
		{"local create_file", "copilot", map[string]any{"hook_event_name": "PreToolUse", "tool_name": "create_file",
			"tool_input": map[string]any{"filePath": target, "content": "b"}}, true, false},
		{"local tool in a CLI body", "copilot", map[string]any{"toolName": "replace_string_in_file",
			"toolArgs": jsonText(map[string]any{"filePath": target, "oldString": "a", "newString": "b"})}, true, false},
		{"local run_in_terminal", "copilot", map[string]any{"tool_name": "run_in_terminal",
			"tool_input": map[string]any{"command": "echo b >> notes.txt", "explanation": "x", "isBackground": false}}, true, false},
		// The finding: the gateway judges toolName, a decoy tool_name hid
		// the patch from the resolver.
		{"decoy snake tool name", "copilot", map[string]any{"toolName": "apply_patch", "tool_name": "read_file", "toolArgs": patch}, true, true},
		{"decoy camel tool name", "copilot", map[string]any{"toolName": "read_file", "tool_name": "apply_patch", "toolArgs": patch}, false, true},
		{"decoy snake arguments", "copilot", map[string]any{"toolName": "bash", "toolArgs": shell,
			"tool_input": map[string]any{"command": "true"}}, true, true},
		{"decoy args alias", "copilot", map[string]any{"toolName": "bash", "toolArgs": shell, "args": map[string]any{"command": "true"}}, true, true},
		{"same tool name twice", "copilot", map[string]any{"toolName": "apply_patch", "tool_name": " apply_patch", "toolArgs": patch}, true, false},
		{"null alias is absent", "copilot", map[string]any{"toolName": "apply_patch", "tool_name": nil, "toolArgs": patch, "tool_input": nil}, true, false},
		// No projection the gateway reads: nothing to describe, but the
		// disagreement still leaves it incomplete.
		{"unreadable toolArgs with a decoy", "copilot", map[string]any{"toolName": "bash", "toolArgs": "not json",
			"tool_input": map[string]any{"command": "true"}}, false, true},
		// Every connector: two spellings that disagree are incomplete.
		{"claude decoy camel arguments", "", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "true"},
			"toolArgs": shell}, false, true},
		{"claude decoy camel tool name", "claudecode", map[string]any{"tool_name": "Bash", "toolName": "Write",
			"tool_input": shell}, true, true},
		{"claude one spelling", "claudecode", map[string]any{"tool_name": "Bash", "tool_input": shell}, true, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			row.body["cwd"] = project
			payload, err := json.Marshal(row.body)
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(ResolveConnector(row.connector, payload))
			if !ok {
				t.Fatal("no decodable write evidence")
			}
			if resolved, listed := targets[target]; listed != row.listed || listed && resolved != target {
				t.Fatalf("listed=%t (%q), want %t: %v", listed, resolved, row.listed, targets)
			}
			if got := targets[TruncatedKey] == "1"; got != row.truncated {
				t.Fatalf("incomplete=%t, want %t: %v", got, row.truncated, targets)
			}
		})
	}
}
