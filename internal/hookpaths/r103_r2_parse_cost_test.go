// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestR103R2BraceExpansionBudget(t *testing.T) {
	for _, tc := range []struct {
		row, command string
	}{
		{"FG3-FIX-0568-B001", `printf x > out/{1..100000000}`},
		{"FG3-FIX-0568-B006", `cp source out/{1..20}{1..30}`},
	} {
		t.Run(tc.row, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			payload, err := json.Marshal(map[string]any{
				"tool_name": "Bash", "cwd": filepath.Join(home, "project"),
				"tool_input": map[string]string{"command": tc.command},
			})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok || targets[TruncatedKey] != "1" {
				t.Fatalf("large brace expansion must yield bounded incomplete evidence: ok=%v truncated=%q", ok, targets[TruncatedKey])
			}
		})
	}
}

func TestR103R2DynamicCandidateProductBudget(t *testing.T) {
	command := `for a in 1 2 3 4 5; do for b in 1 2 3 4 5; do ` +
		`for c in 1 2 3 4 5; do for d in 1 2 3 4 5; do ` +
		`printf x > "$a$b$c$d"; done; done; done; done`
	if _, unknown := ShellDynamicWriteOperands(command, "/project", "/home/user"); !unknown {
		t.Fatal("625 possible targets must short-circuit to incomplete evidence")
	}
}
