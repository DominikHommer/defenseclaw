// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestApplyPatchProjectTargets(t *testing.T) {
	skipWindowsShellFixture(t)
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	envelope := func(body string) string {
		return "*** Begin Patch\n" + body + "*** End Patch\n"
	}
	rows := []struct {
		name, command, cwd string
		want               []string
	}{
		{"project files", "apply_patch <<'PATCH'\n" + envelope("*** Add File: codex.txt\n+x\n*** Update File: README.txt\n@@\n+y\n") + "PATCH", project, []string{filepath.Join(project, "codex.txt"), filepath.Join(project, "README.txt")}},
		{"directory prefix", "cd proj && apply_patch <<'PATCH'\n" + envelope("*** Add File: codex.txt\n+x\n") + "PATCH", home, []string{filepath.Join(project, "codex.txt")}},
		{"directory parent", "cd proj && apply_patch <<'PATCH'\n" + envelope("*** Update File: ../.ssh/authorized_keys\n@@\n+x\n") + "PATCH", home, []string{keys}},
		{"move target", "apply_patch <<'PATCH'\n" + envelope("*** Update File: README.txt\n*** Move to: ../.ssh/authorized_keys\n@@\n+x\n") + "PATCH", project, []string{filepath.Join(project, "README.txt"), keys}},
		{"delete target", "apply_patch <<'PATCH'\n" + envelope("*** Delete File: ../.ssh/authorized_keys\n") + "PATCH", project, []string{keys}},
		{"absolute project file", "apply_patch <<'PATCH'\n" + envelope("*** Add File: "+filepath.Join(project, "codex.txt")+"\n+x\n") + "PATCH", project, []string{filepath.Join(project, "codex.txt")}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got, ok := ApplyPatchWriteTargets("Bash", nil, row.command, row.cwd, home)
			if !ok || len(got) != len(row.want) {
				t.Fatalf("targets = %v, known = %v, want %v", got, ok, row.want)
			}
			for _, name := range row.want {
				if !slices.Contains(got, name) {
					t.Fatalf("targets = %v, want %v", got, row.want)
				}
			}
		})
	}
}
