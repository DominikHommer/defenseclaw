// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellPositionalValueChanges(t *testing.T) {
	skipWindowsShellFixture(t)
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(protected), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(protected, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(cwd, "disklink")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		block         bool
	}{
		{"shift_one", `set -- unused disklink; shift; echo x >> "$1"`, true},
		{"shift_two", `set -- a b disklink; shift 2; echo x >> "$1"`, true},
		{"set_options", `set -f -- unused disklink; shift; echo x >> "$1"`, true},
		{"function_shift", `f(){ shift; echo x >> "$1"; }; f unused disklink`, true},
		{"child_shift", `bash -c 'shift; echo x >> "$1"' _ unused disklink`, true},
		{"shift_count_variable", `n=1; set -- unused disklink; shift "$n"; echo x >> "$1"`, true},
		{"subshell_shift", `set -- unused disklink; (shift; echo x >> "$1")`, true},
		{"guarded_shift", `set -- unused disklink; if true; then shift; fi; echo x >> "$1"`, true},
		{"shifted_list", `set -- unused disklink; shift; for f in "$@"; do echo x >> "$f"; done`, true},
		{"safe_shift", `set -- unused out/a; shift; echo x >> "$1"`, false},
		{"safe_function_shift", `f(){ shift; echo x >> "$1"; }; f unused out/a`, false},
		{"outer_scope", `set -- out/a disklink; (shift); echo x >> "$1"`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			paths, _, dynamic := ShellWriteOperands(row.command, cwd, home)
			candidates, unknown := ShellDynamicWriteOperands(row.command, cwd, home)
			found := dynamic || unknown
			for _, path := range append(paths, candidates...) {
				if strings.Contains(path, "disklink") || strings.Contains(path, "authorized_keys") {
					found = true
				}
			}
			if row.block && !found {
				t.Fatal("protected target was not retained")
			}
			if !row.block && (dynamic || unknown) {
				t.Fatal("ordinary target remains unresolved")
			}
		})
	}
}
