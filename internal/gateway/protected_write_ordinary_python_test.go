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

func TestProtectedWriteOrdinaryPythonCalls(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(project, "build", "report.txt"), []byte("report\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "payload"), []byte("payload\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(project, "disklink")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, code string
		block      bool
	}{
		{"read_encoding", `print(open("build/report.txt", encoding="utf-8").read())`, false},
		{"read_newline", `print(open("build/report.txt", newline="").read())`, false},
		{"read_errors", `print(open("build/report.txt", errors="ignore").read())`, false},
		{"read_buffering", `print(open("build/report.txt", buffering=1).read())`, false},
		{"read_protected_encoding", `print(open("disklink", encoding="utf-8").read())`, false},
		{"copy_file", `import shutil; shutil.copy("payload", "build/report.txt")`, false},
		{"copy2_file", `import shutil; shutil.copy2("payload", "build/report.txt")`, false},
		{"copy_directory", `import shutil; shutil.copy("payload", "build")`, false},
		{"constant_path_binding", `target="build/report.txt"; open(target,"w").write("x")`, false},
		{"write_protected", `open("disklink", mode="a", encoding="utf-8").write("x")`, true},
	}
	for _, row := range rows {
		for _, managed := range []bool{false, true} {
			t.Run(row.name+map[bool]string{false: "/per_user", true: "/managed"}[managed], func(t *testing.T) {
				input := actionfacts.Input{Tool: "Bash", Command: "python3 -c '" + row.code + "'", CWD: project, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
				request := trustedActionRequest{Input: input, ProtectedHomeHook: managed}
				if managed {
					payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": project, "tool_input": map[string]string{"command": input.Command}})
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
