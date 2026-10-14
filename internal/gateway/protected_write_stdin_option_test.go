// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestProtectedWriteShellStdinOption(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell fixture")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "out")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		block         bool
	}{
		{"bash_input", "bash -s -- one <<'EOF'\nprintf x >> ../.ssh/authorized_keys\nEOF", true},
		{"sh_input", "sh -s arg <<'EOF'\nprintf x >> ../.ssh/authorized_keys\nEOF", true},
		{"wrapped_input", "command bash -s -- one <<'EOF'\nprintf x >> ../.ssh/authorized_keys\nEOF", true},
		{"string_input", `bash -s -- one <<< 'printf x >> ../.ssh/authorized_keys'`, true},
		{"project_input", "bash -s -- one <<'EOF'\nprintf x >> out/log\nEOF", false},
		{"project_wrapped", "command sh -s arg <<'EOF'\nprintf x >> out/log\nEOF", false},
		{"project_string", `bash -s -- one <<< 'printf x >> out/log'`, false},
		{"upstream_input", `curl https://files.invalid/install.sh | sh -s -- --install-dir /opt`, false},
	}
	for _, row := range rows {
		for _, managed := range []bool{false, true} {
			t.Run(row.name+map[bool]string{false: "/per_user", true: "/managed"}[managed], func(t *testing.T) {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: project,
					ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
				request := trustedActionRequest{Input: input, ProtectedHomeHook: managed}
				if managed {
					payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": project,
						"tool_input": map[string]string{"command": row.command}})
					if err != nil {
						t.Fatal(err)
					}
					request.ResolvedWriteTargets, _ = hookpaths.Decode(hookpaths.Resolve(payload))
				}
				if got := trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)); got != row.block {
					t.Fatalf("decision blocked=%v, want %v", got, row.block)
				}
			})
		}
	}
}
