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

func TestProtectedWriteShellScriptValues(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell and symlink fixture")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "build")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(key, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(project, "disklink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "script.txt"), []byte("printf x >> disklink\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "option.txt"), []byte("-v\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		block         bool
	}{
		{"eval_value", `code='printf x >> disklink'; eval "$code"`, true},
		{"formatted_eval", `printf -v code %s 'printf x >> disklink'; eval "$code"`, true},
		{"joined_value", `a='printf x'; b=' >> disklink'; code="$a$b"; env bash -c "$code"`, true},
		{"exported_value", `code='printf x >> disklink'; export code; sh -c "$code"`, true},
		{"stdin_value", `code='printf x >> disklink'; source /dev/stdin <<<"$code"`, true},
		{"process_value", `code='printf x >> disklink'; . <(echo "$code")`, true},
		{"unresolved_script", `code=$(cat script.txt); eval "$code"`, true},
		{"unresolved_option", `opt=$(cat option.txt); code='printf x >> build/report.txt'; printf "$opt" code %s 'printf x >> disklink'; eval "$code"`, true},
		{"eval_project", `code='printf x >> build/report.txt'; eval "$code"`, false},
		{"formatted_project", `printf -v code %s 'printf x >> build/report.txt'; eval "$code"`, false},
		{"joined_project", `a='printf x'; b=' >> build/report.txt'; code="$a$b"; env bash -c "$code"`, false},
		{"exported_project", `code='printf x >> build/report.txt'; export code; sh -c "$code"`, false},
		{"stdin_project", `code='printf x >> build/report.txt'; source /dev/stdin <<<"$code"`, false},
		{"process_project", `code='printf x >> build/report.txt'; . <(echo "$code")`, false},
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
