// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestShellVariableWriteCandidates(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	rows := []struct {
		name, command, target string
		unknown               bool
	}{
		{"formatted value", `printf -v f '%s%s' disk link; echo ok >> "$f"`, "disklink", false},
		{"formatted prefix", `printf -v f 'disk%s' link; echo ok >> "$f"`, "disklink", false},
		{"formatted suffix", `printf -v f '%slink' disk; echo ok >> "$f"`, "disklink", false},
		{"loop prefix", `for f in link; do echo ok >> "disk$f"; done`, "disklink", false},
		{"loop infix", `for f in skli; do echo ok >> "di${f}nk"; done`, "disklink", false},
		{"loop ordinary", `for f in one two; do echo ok >> "out/$f.log"; done`, "out/one.log", false},
		{"computed value", `f=other; eval 'f=disklink'; echo ok >> "$f"`, "", true},
		{"input value", `read f <<< disklink; echo ok >> "$f"`, "", true},
		{"conditional default", `f=other; if true; then unset f; fi; echo ok >> "${f:-disklink}"`, "", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			paths, unknown := ShellDynamicWriteOperands(row.command, cwd, home)
			if unknown != row.unknown {
				t.Fatalf("unknown = %v, want %v; paths = %v", unknown, row.unknown, paths)
			}
			if row.target != "" && !slices.Contains(paths, filepath.Join(cwd, row.target)) {
				t.Fatalf("paths = %v, want %q", paths, row.target)
			}
		})
	}
}
