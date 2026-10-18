// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestR103B07R2PositionalWriteRows(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, row := range []struct{ id, command, want string }{
		{"V2-0408-A01", `set -- out/a; echo x >> "$1"`, "out/a"},
		{"V2-0408-A02", `set -- out/a out/b; echo x >> "$2"`, "out/b"},
		{"V2-0408-A03", `set -- ignored out/a; shift; echo x >> "$1"`, "out/a"},
		{"V2-0408-A04", `set -- ignored out/a; shift 1; echo x >> "$1"`, "out/a"},
		{"V2-0408-A05", `f(){ echo x >> "$1"; }; f out/a`, "out/a"},
		{"V2-0408-A06", `f(){ shift; echo x >> "$1"; }; f ignored out/a`, "out/a"},
		{"V3-0408-A01", `set -- out/a disklink; (shift); echo x >> "$1"`, "out/a"},
		{"V3-0408-A02", `set -- ignored out/a; { shift; echo x >> "$1"; }`, "out/a"},
		{"V3-0408-A03", `f(){ set -- ignored out/a; shift; echo x >> "$1"; }; f`, "out/a"},
		{"V3-0408-A04", `f(){ echo x >> "$2"; }; f ignored out/a`, "out/a"},
		{"V3-0408-A05", `set -- ignored out/a; (shift; echo x >> "$1")`, "out/a"},
		{"FG3-FIX-0408-N001", `set -- ignored out/a; shift; echo x >> "$1"`, "out/a"},
		{"FG3-FIX-0408-N002", `f(){ shift; echo x >> "$1"; }; f ignored out/a`, "out/a"},
		{"FG3-FIX-0408-N003", `set -- out/a disklink; (shift); echo x >> "$1"`, "out/a"},
	} {
		t.Run(row.id, func(t *testing.T) {
			want := filepath.Join(cwd, row.want)
			operands, unknown := ShellDynamicWriteOperands(row.command, cwd, home)
			if unknown || len(operands) != 1 || operands[0] != want {
				t.Fatalf("dynamic operands=%v unknown=%v; want %q", operands, unknown, want)
			}
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": row.command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok || targets[TruncatedKey] != "" || targets[want] != want {
				t.Fatalf("incomplete positional write proof: %v (decoded=%v)", targets, ok)
			}
		})
	}
}

func TestR103B07R2PositionalProtectedCompanion(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	command := `set -- "$HOME/.ssh/authorized_keys"; echo x >> "$1"`
	operands, unknown := ShellDynamicWriteOperands(command, cwd, home)
	want := filepath.Join(home, ".ssh", "authorized_keys")
	if unknown || len(operands) != 1 || operands[0] != want {
		t.Fatalf("protected positional target=%v unknown=%v; want %q", operands, unknown, want)
	}
	for _, command := range []string{
		`set -- .ssh/authorized_keys; echo x >> "$1"`,
		`f(){ echo x >> "$1"; }; f .ssh/authorized_keys`,
	} {
		operands, unknown := ShellDynamicWriteOperands(command, home, home)
		if unknown || len(operands) != 1 || operands[0] != want {
			t.Fatalf("cwd=HOME protected positional target=%v unknown=%v; want %q", operands, unknown, want)
		}
	}
}
