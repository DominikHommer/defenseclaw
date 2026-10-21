// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// r104ReviewProtectedWrite runs the protected-file proof the way a per-user
// gateway does (no client map) and the way a managed gateway does (the hook
// client's map, for Claude Code and Codex). It returns the decisions in that
// order.
func r104ReviewProtectedWrite(t *testing.T, command, cwd, home string) []bool {
	t.Helper()
	input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home,
		DialectHint: actionfacts.DialectPOSIX}
	decisions := []bool{trustedExistingAuthorizedKeysSymlinkWrite(trustedActionRequest{Input: input}, actionfacts.Analyze(input))}
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
	if !ok {
		t.Fatal("client proof did not decode")
	}
	for _, connector := range []string{"claudecode", "codex"} {
		request := trustedActionRequest{Input: input, Connector: connector,
			ProtectedHomeHook: true, ResolvedWriteTargets: targets}
		decisions = append(decisions, trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)))
	}
	return decisions
}

func r104ReviewHome(t *testing.T) (home, cwd string) {
	t.Helper()
	home = t.TempDir()
	cwd = filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(protected, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return home, cwd
}

func TestR104ReviewFixDecisions(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	for _, dir := range []string{filepath.Join(cwd, "sub"), filepath.Join(home, ".ssh", "sub")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, command string
		blocked       bool
	}{
		{"called function writer", `f() { python3 -c 'open("alias","a").write("marker")'; }; f`, true},
		{"nested called function writer", `f() { python3 -c 'open("alias","a").write("marker")'; }; g() { f; }; g`, true},
		{"uncalled function writer", `f() { python3 -c 'open("alias","a").write("marker")'; }; echo ok`, false},
		{"bound pattern redirect", `printf -v f %s 'ali*'; echo marker >> $f`, true},
		{"bound pattern loop", `for f in 'ali*'; do echo marker >> $f; done`, true},
		{"quoted bound pattern", `printf -v f %s 'ali*'; echo marker >> "$f"`, false},
		{"search-path cd writes the link", `cd sub && ln -s ../authorized_keys b && echo marker > b`, true},
		{"search-path cd writes another file", `cd sub && ln -s ../a b && echo marker > out.txt`, false},
		{"explicit cd writes the link", `cd ./sub && ln -s ../authorized_keys b && echo marker > b`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, got := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if got != tc.blocked {
					t.Fatalf("decision %d (per-user, managed claudecode, managed codex) = %v, want %v", i, got, tc.blocked)
				}
			}
		})
	}
}
