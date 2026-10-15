// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestShellDirectoryWriteOperands_StatementWithoutCommand(t *testing.T) {
	cwd := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{">first", ">>first", ">first <<< data"} {
		t.Run(prefix, func(t *testing.T) {
			command := prefix + "; echo done >second"
			got, unknown := ShellDirectoryWriteOperands(command, cwd, home, nil, true, false)
			if unknown || len(got) != 0 {
				t.Fatalf("directory operands=%v unknown=%v, want none", got, unknown)
			}
			operands, parsed, _ := ShellWriteOperands(command, cwd, home)
			want := []string{filepath.Join(cwd, "first"), filepath.Join(cwd, "second")}
			if !parsed || !reflect.DeepEqual(operands, want) {
				t.Fatalf("redirect operands=%v parsed=%v, want %v", operands, parsed, want)
			}
			body, err := json.Marshal(map[string]any{
				"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]any{"command": command},
			})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(body))
			if !ok || targets[filepath.Join(cwd, "first")] == "" || targets[filepath.Join(cwd, "second")] == "" {
				t.Fatalf("public resolve targets=%v valid=%v", targets, ok)
			}
		})
	}
}

func TestShellDirectoryWriteOperands_OrdinaryCommands(t *testing.T) {
	cwd := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		command string
		paths   []string
	}{
		{"echo done >one", []string{"one"}},
		{"echo done >>one; cat one >two", []string{"one", "two"}},
		{"(echo done >one); echo done >two", []string{"one", "two"}},
	} {
		got, unknown := ShellDirectoryWriteOperands(tc.command, cwd, home, nil, true, false)
		if unknown || len(got) != 0 {
			t.Errorf("%q: directory operands=%v unknown=%v, want none", tc.command, got, unknown)
		}
		redirects, parsed, _ := ShellWriteOperands(tc.command, cwd, home)
		want := make([]string, len(tc.paths))
		for i, path := range tc.paths {
			want[i] = filepath.Join(cwd, path)
		}
		if !parsed || !reflect.DeepEqual(redirects, want) {
			t.Errorf("%q: redirects=%v parsed=%v, want %v", tc.command, redirects, parsed, want)
		}
	}
}

func TestShellDirectoryWriteOperands_ContinuesAfterStatementWithoutCommand(t *testing.T) {
	cwd := t.TempDir()
	if err := os.Mkdir(filepath.Join(cwd, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	got, unknown := ShellDirectoryWriteOperands(">first; cd child; echo done >second", cwd, home, nil, true, false)
	want := []RedirectOccurrence{{Path: filepath.Join(cwd, "child", "second")}}
	if unknown || !reflect.DeepEqual(got, want) {
		t.Fatalf("directory operands=%v unknown=%v, want %v", got, unknown, want)
	}
}

func TestShellDirectoryWriteOperands_StatementForms(t *testing.T) {
	cwd := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	forms := []string{
		">x; echo ok", ">>x; echo ok", "2>x; echo ok", "2>>x; echo ok",
		"1>x; echo ok", "1>>x; echo ok", "&>x; echo ok", "&>>x; echo ok",
		"<>x; echo ok", ">|x; echo ok", ">x 2>y; echo ok", ">>x 2>>y; echo ok",
		"<<< data; echo ok", ">x <<< data; echo ok", "2>x <<< data; echo ok",
		">x && echo ok", ">x || echo ok", ">x | cat", "(>x; echo ok)",
		"{ >x; echo ok; }", "{ >>x; } ; echo ok", "(>x) && echo ok",
		"<<EOF\ndata\nEOF\necho ok", "<<'EOF'\ndata\nEOF\necho ok",
	}
	for _, command := range forms {
		t.Run(command, func(t *testing.T) {
			if _, parsed := parseShell(command); !parsed {
				t.Fatal("fixture did not parse")
			}
			_, _ = ShellDirectoryWriteOperands(command, cwd, home, nil, true, false)
		})
	}
}
