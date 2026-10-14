// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestSedStdinScriptOperands(t *testing.T) {
	skipWindowsShellFixture(t)
	cwd := filepath.Join(t.TempDir(), "proj")
	home := filepath.Dir(cwd)
	rows := []struct {
		name, command, target string
	}{
		{"here string", `sed -n -f /dev/stdin payload <<< 'w disklink'`, "disklink"},
		{"here document", "sed -n -f - payload <<'EOF'\nw disklink\nEOF", "disklink"},
		{"long option", `sed -n --file=/dev/stdin payload <<< 'w disklink'`, "disklink"},
		{"ordinary output", `sed -n -f /dev/stdin payload <<< 'w out/log'`, "out/log"},
		{"read only", `sed -n -f /dev/stdin payload <<< 'p'`, ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			paths, unknown := LiteralWriteAnalysis(row.command, cwd, home)
			if unknown {
				t.Fatalf("script target is unknown")
			}
			if row.target == "" {
				if len(paths) != 0 {
					t.Fatalf("targets = %v, want none", paths)
				}
				return
			}
			if !slices.Contains(paths, filepath.Join(cwd, row.target)) {
				t.Fatalf("targets = %v, want %s", paths, row.target)
			}
		})
	}
}
