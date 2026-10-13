// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBoundedOrdinaryWriteTargets(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0700); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, command string }{
		{"temporary name", `echo x > "$(mktemp -u)"`},
		{"assigned numeric name", `f=out/$(date +%s).log; echo x > $f`},
		{"formatted number", `printf -v n '%03d' 5; echo x > out/$n.log`},
		{"temporary directory", `tmp=$(mktemp -d); trap 'rm -rf $tmp' EXIT; echo x > $tmp/a`},
		{"array element", `A=(a b); echo x > out/${A[1]}`},
		{"positional word", `set -- out; echo x > $1/z`},
		{"direct numeric name", `git diff > out/$(date +%Y%m%d).patch`},
		{"temporary parent", `cd /tmp && echo x > $(mktemp -p /tmp)`},
		{"user name", `echo x > "out/$(whoami).log"`},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_, unknown := ShellDynamicWriteOperands(row.command, cwd, home)
			if unknown {
				t.Fatal("ordinary target remains unknown")
			}
		})
	}
}

func TestBoundedValueProtectedAliases(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(protected, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"005.log", "2026.log", "person.log"} {
		if err := os.Symlink(protected, filepath.Join(cwd, "out", name)); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct{ name, command string }{
		{"formatted number", `printf -v n '%03d' 5; echo x > out/$n.log`},
		{"numeric domain", `echo x > out/$(date +%Y).log`},
		{"name domain", `echo x > "out/$(whoami).log"`},
		{"protected temporary parent", `echo x > "$(mktemp -p ../.ssh)"`},
		{"array element", `A=(out/log ../.ssh/authorized_keys); echo x > ${A[1]}`},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			paths, _, _ := ShellWriteOperands(row.command, cwd, home)
			candidates, unknown := ShellDynamicWriteOperands(row.command, cwd, home)
			if !unknown && len(paths) == 0 && len(candidates) == 0 {
				t.Fatal("protected alias was not retained")
			}
		})
	}
}
