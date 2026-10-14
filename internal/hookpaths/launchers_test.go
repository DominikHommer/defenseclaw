// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestLauncherWriteOperands(t *testing.T) {
	skipWindowsShellFixture(t)
	cwd := filepath.Join(t.TempDir(), "proj")
	home := filepath.Dir(cwd)
	target := filepath.Join(cwd, "disklink")
	rows := []struct {
		name, command string
		want          bool
	}{
		{"env short option", `env -i python3 -c 'open("disklink","a").write("x")'`, true},
		{"env long option", `env --unset=UNUSED node -e 'require("fs").appendFileSync("disklink","x")'`, true},
		{"env split string", `env -S 'python3 -c "open(\"disklink\",\"a\").write(\"x\")"'`, true},
		{"command prefix", `command -p cp payload disklink`, true},
		{"nested prefix", `env A=1 nice -n 5 cp payload disklink`, true},
		{"shell command", `bash -c 'cp payload disklink'`, true},
		{"multicall", `busybox cp payload disklink`, true},
		{"find child", `find disklink -exec cp payload {} \;`, true},
		{"xargs child", `printf disklink | xargs -I{} cp payload {}`, true},
		{"numa prefix", `numactl --localalloc cp payload disklink`, true},
		{"flock command", `flock lockfile -c 'cp payload disklink'`, true},
		{"env ordinary", `env -i python3 -c 'open("notes.txt","a").write("x")'`, false},
		{"command lookup", `command -v cp > notes.txt`, false},
		{"nested ordinary", `env A=1 nice -n 5 cp payload notes.txt`, false},
		{"find data", `for dir in src docs; do find "$dir" -type f >> out/file-list.txt; done`, false},
		{"xargs ordinary", `printf notes.txt | xargs -I{} cp payload {}`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			var paths []string
			paths = append(paths, LiteralWriteOperands(row.command, cwd, home)...)
			for _, operand := range ShellExtraWriteOperands(row.command, cwd, home) {
				paths = append(paths, operand.Path)
			}
			if got := slices.Contains(paths, target); got != row.want {
				t.Fatalf("target listed = %v, want %v; paths=%v", got, row.want, paths)
			}
		})
	}
}
