// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPythonOrdinaryFileCalls(t *testing.T) {
	skipWindowsShellFixture(t)
	home := t.TempDir()
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
	if err := os.Symlink(key, filepath.Join(project, "disklink")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, code string
		want       string
	}{
		{"read_encoding", `print(open("build/report.txt", encoding="utf-8").read())`, ""},
		{"read_newline", `print(open("build/report.txt", newline="").read())`, ""},
		{"read_errors", `print(open("build/report.txt", errors="ignore").read())`, ""},
		{"read_buffering", `print(open("build/report.txt", buffering=1).read())`, ""},
		{"read_mode_keyword", `print(open("build/report.txt", mode="r", encoding="utf-8").read())`, ""},
		{"read_protected_encoding", `print(open("disklink", encoding="utf-8").read())`, ""},
		{"write_mode_keyword", `open("build/report.txt", encoding="utf-8", mode="a").write("x")`, "build/report.txt"},
		{"constant_path_binding", `target="build/report.txt"; open(target,"w").write("x")`, "build/report.txt"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			paths, unknown := literalInterpreterAnalysis("python", row.code, project, home)
			if unknown {
				t.Fatal("ordinary call left unresolved")
			}
			if row.want == "" && len(paths) != 0 || row.want != "" && (len(paths) != 1 || paths[0] != row.want) {
				t.Fatalf("paths=%v, want %q", paths, row.want)
			}
		})
	}
}
