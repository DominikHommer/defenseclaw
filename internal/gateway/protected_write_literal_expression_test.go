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

func TestProtectedWriteLiteralExpressions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell fixture")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "build")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys2"), []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		block         bool
	}{
		{"python_joined", `python3 -c 'open("../.ssh/" + "authorized_keys2","a").write("x")'`, true},
		{"python_project", `python3 -c 'open("build/" + "report.txt","a").write("x")'`, false},
		{"python_path_join", `python3 -c 'import os; open(os.path.join("..",".ssh","authorized_keys2"),"a").write("x")'`, true},
		{"python_project_join", `python3 -c 'import os; open(os.path.join("build","report.txt"),"a").write("x")'`, false},
		{"node_joined", `node -e 'require("fs").writeFileSync("../.ssh/"+"authorized_keys2","x")'`, true},
		{"node_project", `node -e 'require("fs").writeFileSync("build/"+"report.txt","x")'`, false},
		{"perl_joined", `perl -e 'open(F,">>","../.ssh/" . "authorized_keys2"); print F "x"'`, true},
		{"perl_project", `perl -e 'open(F,">>","build/" . "report.txt"); print F "x"'`, false},
		{"ruby_joined", `ruby -e 'File.write("../.ssh/" + "authorized_keys2","x")'`, true},
		{"ruby_project", `ruby -e 'File.write("build/" + "report.txt","x")'`, false},
		{"awk_joined", `gawk 'BEGIN{a="../.ssh/"; b="authorized_keys2"; print "x" >> (a b)}'`, true},
		{"awk_project", `gawk 'BEGIN{a="build/"; b="report.txt"; print "x" >> (a b)}'`, false},
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
