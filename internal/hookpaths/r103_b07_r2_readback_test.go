// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestR103B07R2ReadBackRows(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, row := range []struct{ id, command string }{
		{"V2-0567-A01", `printf '%s\n' out/entry.txt > choice.txt; read -r d < choice.txt; printf x > "$d"`},
		{"V2-0567-A02", `echo out/entry.txt > choice.txt; read -r d < choice.txt; echo x >> "$d"`},
		{"V2-0567-A05", `printf '%s\n' out/entry.txt > ./choice.txt; read -r d < choice.txt; cat /dev/null > "$d"`},
		{"V3-0567-A01", `printf '%s\n' out/entry.txt > choice.txt; read -r d < ./choice.txt; printf x > "$d"`},
		{"V3-0567-A02", `echo out/entry.txt > choice.txt; read -r d < choice.txt; echo x >> "$d"`},
		{"V3-0567-A05", `printf '%s\n' out/entry.txt > choice.txt; read -r d < choice.txt; cat /dev/null > "$d"`},
		{"V3-0567-A06", `printf '%s\n' out/entry.txt > ./choice.txt; read -r d < ./choice.txt; printf x > "$d"`},
	} {
		t.Run(row.id, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": row.command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			want := filepath.Join(cwd, "out", "entry.txt")
			if !ok || targets[TruncatedKey] != "" || targets[want] != want {
				t.Fatalf("read-back target proof incomplete: %v, decode=%v", targets, ok)
			}
		})
	}
}
