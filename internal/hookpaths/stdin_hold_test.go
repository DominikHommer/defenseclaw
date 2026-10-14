// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestStdinProgramOperands(t *testing.T) {
	skipWindowsShellFixture(t)
	cwd := filepath.Join(t.TempDir(), "proj")
	home := filepath.Dir(cwd)
	protected := filepath.Join(cwd, "disklink")
	rows := []struct {
		name, command string
		path, dynamic bool
	}{
		{"direct operand", `echo disklink | xargs truncate -s 5`, true, false},
		{"shell operand", `echo disklink | xargs -I{} sh -c 'echo x >> {}'`, false, true},
		{"ordinary operand", `echo notes.txt | xargs truncate -s 5`, false, false},
		{"reader operand", `echo disklink | xargs cat`, false, false},
		{"copy source", `echo disklink | xargs -I{} cp {} notes.txt`, false, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			paths, _, dynamic := ShellWriteOperands(row.command, cwd, home)
			for _, operand := range ShellExtraWriteOperands(row.command, cwd, home) {
				paths = append(paths, operand.Path)
			}
			if got := slices.Contains(paths, protected); got != row.path {
				t.Fatalf("target listed = %v, want %v", got, row.path)
			}
			if dynamic != row.dynamic {
				t.Fatalf("dynamic target = %v, want %v", dynamic, row.dynamic)
			}
		})
	}
}

func TestStdinUnknownWritePositions(t *testing.T) {
	skipWindowsShellFixture(t)
	cwd := filepath.Join(t.TempDir(), "proj")
	home := filepath.Dir(cwd)
	rows := []struct {
		name, command string
		want          bool
	}{
		{"direct destination", `cat names.txt | xargs truncate -s 5`, true},
		{"replacement destination", `cat names.txt | xargs -I{} cp payload {}`, true},
		{"replacement source", `cat names.txt | xargs -I{} cp {} notes.txt`, false},
		{"reader operand", `cat names.txt | xargs wc -c`, false},
		{"shell destination", `echo disklink | xargs -I{} sh -c 'echo x >> {}'`, true},
		{"known direct destination", `echo disklink | xargs truncate -s 5`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if got := ShellStdinWriteUnknown(row.command, cwd, home); got != row.want {
				t.Fatalf("unknown write = %v, want %v", got, row.want)
			}
		})
	}
}
