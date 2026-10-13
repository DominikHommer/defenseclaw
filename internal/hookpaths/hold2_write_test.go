// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestShellProgramValuesAndOperands(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	protected := filepath.Join(cwd, "disklink")
	if err := os.Mkdir(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(protected, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		want          bool
	}{
		{"program variable", `T=tee; $T -a disklink < payload`, true},
		{"program phrase", `T='tee -a'; $T disklink < payload`, true},
		{"copy program", `P=cp; $P payload disklink`, true},
		{"glob operand", `tee -a disk* < payload`, true},
		{"computed operand", `echo x | tee -a $(echo disklink)`, true},
		{"output assignment", `dd if=payload of=$(echo disklink)`, true},
		{"ordinary program", `T=tee; $T -a out/log < payload`, false},
		{"ordinary computed operand", `echo x | tee -a $(echo out/log)`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			var paths []string
			paths = append(paths, LiteralWriteOperands(row.command, cwd, home)...)
			redirects, _, _ := ShellWriteOperands(row.command, cwd, home)
			paths = append(paths, redirects...)
			for _, operand := range ShellExtraWriteOperands(row.command, cwd, home) {
				paths = append(paths, operand.Path)
			}
			if got := slices.Contains(paths, protected); got != row.want {
				t.Fatalf("target listed = %v, want %v; paths=%v", got, row.want, paths)
			}
		})
	}
}

func TestLiteralChildWriterClasses(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	protected := filepath.Join(cwd, "disklink")
	rows := []struct {
		name, command string
		want          bool
	}{
		{"python process", `python3 -c 'import os; os.system("echo x >> disklink")'`, true},
		{"python shell process", `python3 -c 'import subprocess; subprocess.run("echo x >> disklink", shell=True)'`, true},
		{"node process", `node -e 'require("child_process").execSync("echo x >> disklink")'`, true},
		{"perl process", `perl -e 'system("echo x >> disklink")'`, true},
		{"awk process", `awk 'BEGIN{system("echo x >> disklink")}'`, true},
		{"sed write command", `sed -n 'w disklink' payload`, true},
		{"sed substitution write", `sed 's/^/x/w disklink' payload`, true},
		{"ordinary child", `python3 -c 'import os; os.system("echo x >> out/log")'`, false},
		{"ordinary sed", `sed -n 'w out/log' payload`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			var paths []string
			paths = append(paths, LiteralWriteOperands(row.command, cwd, home)...)
			for _, operand := range ShellExtraWriteOperands(row.command, cwd, home) {
				paths = append(paths, operand.Path)
			}
			if got := slices.Contains(paths, protected); got != row.want {
				t.Fatalf("target listed = %v, want %v; paths=%v", got, row.want, paths)
			}
		})
	}
}
