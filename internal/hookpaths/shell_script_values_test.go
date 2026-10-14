// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBoundedShellScriptValues(t *testing.T) {
	skipWindowsShellFixture(t)
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
		{"shell_value", `code='printf x >> disklink'; bash -c "$code"`, true},
		{"eval_value", `code='printf x >> disklink'; eval "$code"`, true},
		{"formatted_eval", `printf -v code %s 'printf x >> disklink'; eval "$code"`, true},
		{"joined_value", `a='printf x'; b=' >> disklink'; code="$a$b"; env bash -c "$code"`, true},
		{"exported_value", `code='printf x >> disklink'; export code; sh -c "$code"`, true},
		{"stdin_value", `code='printf x >> disklink'; source /dev/stdin <<<"$code"`, true},
		{"process_value", `code='printf x >> disklink'; . <(echo "$code")`, true},
		{"launcher_value", `code='printf x >> disklink'; command bash -c "$code"`, true},
		{"shell_project", `code='printf x >> build/report.txt'; bash -c "$code"`, false},
		{"eval_project", `code='printf x >> build/report.txt'; eval "$code"`, false},
		{"formatted_project", `printf -v code %s 'printf x >> build/report.txt'; eval "$code"`, false},
		{"joined_project", `a='printf x'; b=' >> build/report.txt'; code="$a$b"; env bash -c "$code"`, false},
		{"exported_project", `code='printf x >> build/report.txt'; export code; sh -c "$code"`, false},
		{"stdin_project", `code='printf x >> build/report.txt'; source /dev/stdin <<<"$code"`, false},
		{"process_project", `code='printf x >> build/report.txt'; . <(echo "$code")`, false},
		{"launcher_project", `code='printf x >> build/report.txt'; command bash -c "$code"`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": project,
				"tool_input": map[string]string{"command": row.command}})
			if err != nil {
				t.Fatal(err)
			}
			facts, ok := Decode(Resolve(payload))
			if !ok {
				t.Fatal("invalid analysis evidence")
			}
			found := false
			for _, value := range facts {
				found = found || value == key
			}
			if row.block && !found {
				t.Fatal("protected script target was not resolved")
			}
			if !row.block && (found || facts[TruncatedKey] == "1") {
				t.Fatal("ordinary script evidence incomplete")
			}
		})
	}
	for _, command := range []string{
		`code=$(cat script.txt); eval "$code"`,
		`opt=$(cat option.txt); code='printf x >> build/report.txt'; printf "$opt" code %s 'printf x >> disklink'; eval "$code"`,
	} {
		payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": project,
			"tool_input": map[string]string{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		facts, ok := Decode(Resolve(payload))
		if !ok || facts[TruncatedKey] != "1" {
			t.Fatal("unresolved script text did not mark analysis incomplete")
		}
	}
}
