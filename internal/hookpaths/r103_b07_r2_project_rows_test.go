// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestR103B07R2ProjectValueRowsByID(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, dir := range []string{"out/a", "out/b"} {
		if err := os.MkdirAll(filepath.Join(cwd, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	rows := []struct {
		id, command string
		want        []string
	}{
		{"FG3-HOLD3-N0045", `for d in out/*; do printf x > "$d/entry.txt"; done`, []string{"out/a/entry.txt", "out/b/entry.txt"}},
		{"FG3-HOLD3-N0052", `x=out; printf x > "${x:0}/entry.txt"`, []string{"out/entry.txt"}},
		{"FG3-HOLD3-N0056", `printf x > "$PWD/out/entry.txt"`, []string{"out/entry.txt"}},
		{"FG3-HOLD3-N0057", `for d in out/*; do printf x > "$d/entry.txt"; done`, []string{"out/a/entry.txt", "out/b/entry.txt"}},
		{"FG3-HOLD3-N0058", `x=out; echo x >> "${x:0}/entry.txt"`, []string{"out/entry.txt"}},
		{"FG3-HOLD3-N0061", `for d in out/*; do echo x >> "$d/entry.txt"; done`, []string{"out/a/entry.txt", "out/b/entry.txt"}},
		{"FG3-HOLD3-N0064", `printf x > "$PWD/out/entry.txt"`, []string{"out/entry.txt"}},
		{"FG3-HOLD3-N0065", `for d in out/*; do printf x > "$d/entry.txt"; done`, []string{"out/a/entry.txt", "out/b/entry.txt"}},
		{"HOLD3-N0045", `for d in out/*; do printf x > "$d/entry.txt"; done`, []string{"out/a/entry.txt", "out/b/entry.txt"}},
		{"HOLD3-N0052", `x=out; printf x > "${x:0}/entry.txt"`, []string{"out/entry.txt"}},
		{"HOLD3-N0056", `printf x > "$PWD/out/entry.txt"`, []string{"out/entry.txt"}},
		{"HOLD3-N0057", `for d in out/*; do printf x > "$d/entry.txt"; done`, []string{"out/a/entry.txt", "out/b/entry.txt"}},
		{"HOLD3-N0058", `x=out; echo x >> "${x:0}/entry.txt"`, []string{"out/entry.txt"}},
		{"HOLD3-N0061", `for d in out/*; do echo x >> "$d/entry.txt"; done`, []string{"out/a/entry.txt", "out/b/entry.txt"}},
		{"HOLD3-N0064", `printf x > "$PWD/out/entry.txt"`, []string{"out/entry.txt"}},
		{"HOLD3-N0065", `for d in out/*; do printf x > "$d/entry.txt"; done`, []string{"out/a/entry.txt", "out/b/entry.txt"}},
	}
	for _, row := range rows {
		t.Run(row.id, func(t *testing.T) { assertR103B07R2Resolved(t, cwd, row.command, row.want) })
	}
}

func TestR103B07R2OrdinaryProjectRowsByID(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(cwd, "tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, row := range []struct{ id, command string }{
		{"FG3-FIX-0382-A03-N", `d=$(printf %s "$PWD"); printf x > "$d/tmp/output.txt"`},
		{"FG3-FIX-0382-A04-N", `d=$(dirname "$PWD/tmp/leaf"); printf x > "$d/output.txt"`},
		{"FG3-FIX-0409-A01-N", `d=$(printf %s "$PWD"); echo x >> "$d/tmp/output.txt"`},
		{"FG3-FIX-0409-A06-N", `d=$(dirname "$PWD/tmp/leaf"); echo x >> "$d/output.txt"`},
		{"FG3-FIX-B-02-A01-N", `d=$(printf %s "$PWD"); printf x > "$d/tmp/output.txt"`},
		{"FG3-FIX-B-04-A01-N", `d=$(dirname "$PWD/tmp/leaf"); printf x > "$d/output.txt"`},
		{"FG3-FIX-SHELL-N101", `d=$(printf %s "$PWD"); printf x > "$d/tmp/output.txt"`},
		{"FG3-FIX-SHELL-N102", `d=$(dirname "$PWD/tmp/leaf"); printf x > "$d/output.txt"`},
		{"FG3-FIX-SHELL-N104", `d=$(printf %s "$PWD"); echo x >> "$d/tmp/output.txt"`},
		{"FG3-FIX-SHELL-N105", `d=$(dirname "$PWD/tmp/leaf"); echo x >> "$d/output.txt"`},
		{"V2-0382-A03", `d=$(printf %s "$PWD"); printf x > "$d/tmp/output.txt"`},
		{"V3-0382-A05", `d=$(dirname "$PWD/tmp/leaf"); printf x > "$d/output.txt"`},
	} {
		t.Run(row.id, func(t *testing.T) { assertR103B07R2Resolved(t, cwd, row.command, []string{"tmp/output.txt"}) })
	}
}

func TestR103B07R2LiteralWorkspaceLoopRowsByID(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	ids := []string{"B-REAL-00080", "B-REAL-00286", "B-REAL-00521", "B-REAL-00551", "B-REAL-00555", "B-REAL-01300", "B-REAL-01455", "B-REAL-01942", "B-REAL-02034", "B-REAL-02758", "B-REAL-03080", "B-REAL-03500", "B-REAL-03599", "B-REAL-03945", "B-REAL-03989", "B-REAL-04030", "B-REAL-04594", "B-REAL-04596", "B-REAL-04693", "B-REAL-05174"}
	t.Setenv("HOME", home)
	for i, id := range ids {
		t.Run(id, func(t *testing.T) {
			count := 17 + i%10
			dirs, want := make([]string, 0, count), make([]string, 0, count)
			for n := 0; n < count; n++ {
				name := "workspace" + strconv.Itoa(n)
				if err := os.MkdirAll(filepath.Join(cwd, name), 0700); err != nil {
					t.Fatal(err)
				}
				dirs = append(dirs, name)
				want = append(want, name+"/out.txt")
			}
			command := `for d in ` + strings.Join(dirs, " ") + `; do printf x > "$d/out.txt"; done`
			assertR103B07R2Resolved(t, cwd, command, want)
		})
	}
}

func TestR103B07R2ProjectGlobProtectedAlias(t *testing.T) {
	home := t.TempDir()
	for _, dir := range []string{"out", ".ssh"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(home, "out", "alias")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	command := `for d in out/*; do printf x > "$d/authorized_keys"; done`
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": home,
		"tool_input": map[string]string{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(payload))
	if !ok || targets[TruncatedKey] != "" || targets[filepath.Join(home, "out", "alias", "authorized_keys")] != keys {
		t.Fatalf("cwd=HOME glob alias was not identified: targets=%v decode=%v", targets, ok)
	}
}

func TestR103B07R2ProjectGlobLimit(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for i := 0; i <= MaxWriteTargets; i++ {
		if err := os.MkdirAll(filepath.Join(cwd, "out", strconv.Itoa(i)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": `for d in out/*; do printf x > "$d/entry.txt"; done`}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(payload))
	if !ok || targets[TruncatedKey] != "1" {
		t.Fatalf("unbounded glob must remain incomplete: targets=%v decode=%v", targets, ok)
	}
}

func assertR103B07R2Resolved(t *testing.T, cwd, command string, want []string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(payload))
	if !ok || targets[TruncatedKey] != "" {
		t.Fatalf("target proof incomplete: %v, decode=%v", targets, ok)
	}
	for _, path := range want {
		absolute := filepath.Join(cwd, path)
		if targets[absolute] != absolute {
			t.Fatalf("target %q = %q, all=%v", absolute, targets[absolute], targets)
		}
	}
}
