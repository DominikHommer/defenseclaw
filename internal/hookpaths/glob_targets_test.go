// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLiteralGlobRedirectCandidates(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "result"), 0700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(key, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "notes-one.txt"), []byte("notes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(cwd, "out-key.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(cwd, "prior-key.txt")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command, target string
		unknown               bool
	}{
		{"ordinary match", `echo ok > notes-*.txt`, filepath.Join(cwd, "notes-one.txt"), false},
		{"ordinary unmatched", `echo ok > report-*.txt`, filepath.Join(cwd, "report-*.txt"), false},
		{"launcher list short", `sudo -l > report-*.txt`, filepath.Join(cwd, "report-*.txt"), false},
		{"launcher list long", `sudo --list > report-*.txt`, filepath.Join(cwd, "report-*.txt"), false},
		{"linked match", `echo ok > out-*.txt`, filepath.Join(cwd, "out-key.txt"), false},
		{"protected match", `echo ok > ../.ssh/authorized_key*`, key, false},
		{"variable pattern", `echo ok > "$F"*.txt`, "", true},
		{"created link", `ln -s ../.ssh/authorized_keys out-new.txt; echo ok > out-*.txt`, "", true},
		{"changed match set", `mv prior-key.txt result-key.txt; echo ok > result-*.txt`, "", true},
		{"changed directory match", `mv prior-key.txt result/; echo ok > result/prior-*.txt`, "", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			paths, unknown := ShellDynamicWriteOperands(row.command, cwd, home)
			if unknown != row.unknown {
				t.Fatalf("unknown = %v, want %v; paths = %v", unknown, row.unknown, paths)
			}
			if row.target != "" && !slices.Contains(paths, row.target) {
				t.Fatalf("paths = %v, want %q", paths, row.target)
			}
		})
	}
}

func TestMissingGlobParent(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "missing", "project")
	paths, unknown := ShellDynamicWriteOperands(`echo ok > out-*.txt`, cwd, home)
	if unknown || len(paths) != 0 {
		t.Fatalf("paths = %v, unknown = %v", paths, unknown)
	}
}
