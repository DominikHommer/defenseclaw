// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"strings"
	"testing"
)

// An f- or t-string runs its replacement fields, so only inert comments and
// triple-quoted strings are blanked; source the scan cannot follow is left
// whole (fail closed).
func TestMaskPythonCommentsAndDocstringsKeepsExecutedText(t *testing.T) {
	const write = "p.write_text("
	for _, tc := range []struct {
		name, source string
		visible      bool
	}{
		{"comment", "x = 1  # p.write_text(\"k\")\n", false},
		{"docstring", `"""p.write_text("k")"""` + "\nprint(1)\n", false},
		{"bytes docstring", `b"""p.write_text("k")"""`, false},
		{"docstring after an f-string", `print(f"{1}"); """p.write_text("k")"""`, false},
		{"name ending in a prefix letter", `if"""p.write_text("k")""" in x: pass`, false},
		{"code", `p.write_text("k")`, true},
		{"f-string field", `f"""{p.write_text("k")}"""`, true},
		{"raw f-string field", `rF'''{p.write_text("k")}'''`, true},
		{"template string field", `t"""{p.write_text("k")}"""`, true},
		{"same quotes in a field", `f"""{"""a""" + str(p.write_text("k"))}"""`, true},
		{"format spec field", `f"""{x:{p.write_text("k")}}"""`, true},
		{"code after an escaped quote", `x = """a\""""; p.write_text("k")`, true},
		{"code after an f-string", `f"""{x!r:>{w}}"""; p.write_text("k")`, true},
		{"unclosed field", `f"""{p.write_text("k")"""`, true},
		{"unclosed docstring", `"""p.write_text("k")`, true},
	} {
		masked := MaskPythonCommentsAndDocstrings(tc.source)
		if len(masked) != len(tc.source) {
			t.Fatalf("%s: masked length %d, want %d", tc.name, len(masked), len(tc.source))
		}
		if got := strings.Contains(masked, write); got != tc.visible {
			t.Errorf("%s: %q masked to %q: write visible=%t, want %t", tc.name, tc.source, masked, got, tc.visible)
		}
	}
}
