// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestLauncherProgramFamilies(t *testing.T) {
	skipWindowsShellFixture(t)
	cwd := filepath.Join(t.TempDir(), "proj")
	home := filepath.Dir(cwd)
	protected := filepath.Join(cwd, "disklink")
	rows := []struct {
		name, command string
		want          bool
	}{
		{"legacy adjustment", `nice -5 tee -a disklink < payload`, true},
		{"unknown prefix", `fakeroot tee -a disklink < payload`, true},
		{"unknown options", `strace -f -o /dev/null python3 -c 'open("disklink","a").write("x")'`, true},
		{"unknown shell child", `eatmydata sh -c 'echo x >> disklink'`, true},
		{"unknown child after separator", `proxychains -- truncate -s 5 disklink`, true},
		{"reader data", `cat disklink`, false},
		{"reader program name", `man cp`, false},
		{"reader option", `grep tee disklink`, false},
		{"ordinary prefix", `fakeroot tee -a notes.txt < payload`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			var paths []string
			paths = append(paths, LiteralWriteOperands(row.command, cwd, home)...)
			pathsFromRedirs, _, _ := ShellWriteOperands(row.command, cwd, home)
			paths = append(paths, pathsFromRedirs...)
			for _, operand := range ShellExtraWriteOperands(row.command, cwd, home) {
				paths = append(paths, operand.Path)
			}
			if got := slices.Contains(paths, protected); got != row.want {
				t.Fatalf("target listed = %v, want %v; paths=%v", got, row.want, paths)
			}
		})
	}
}

func TestTerminalProgramOperands(t *testing.T) {
	skipWindowsShellFixture(t)
	for _, words := range [][]string{
		{"groupmems", "-g", "sudo", "-a", "agent"},
		{"usermod", "-g", "tee", "agent"},
		{"groupadd", "--", "cp"},
	} {
		result := resolveLauncherWords(words, makeStatic(len(words)), "/repo")
		if !result.ok || result.noExec || len(result.words) != len(words) || result.words[0] != words[0] {
			t.Fatalf("program operands changed for %q", words[0])
		}
	}
}
