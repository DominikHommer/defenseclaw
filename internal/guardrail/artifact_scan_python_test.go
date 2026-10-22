// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
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
		// The literal text of an f-string is inert; only its fields run.
		{"f-string literal text", `f"""p.write_text("k")"""`, false},
		{"raw f-string literal text", `Rf'''p.write_text("k")'''`, false},
		{"template string literal text", `t"""p.write_text("k") {x}"""`, false},
		{"f-string text after a field", `f"""{x!r:>{w}} p.write_text("k")"""`, false},
		{"f-string text beside a field that writes", `f"""p.write_text {p.write_text("k")}"""`, true},
		{"f-string escaped braces are text", `f"""{{p.write_text("k")}}"""`, false},
		// Format spec text is literal; its nested fields run.
		{"format spec text", `f"""{x:p.write_text("k")}"""`, false},
		{"format spec text after a conversion", `f"""{x!r:p.write_text("k")}"""`, false},
		{"format spec text after a nested field", `f"""{x:{w}p.write_text("k")}"""`, false},
		{"multiline f-string field", "f\"\"\"a\n{\n p.write_text(\"k\")\n}\nb\"\"\"", true},
		{"single-quoted f-string", `f"p.write_text('k')"`, true},
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

// MaskPythonStrings leaves only the code that runs: the text of every string
// is blanked, f-string fields are kept with their own strings blanked.
func TestMaskPythonStringsKeepsOnlyCode(t *testing.T) {
	const write = "p.write_text("
	for _, tc := range []struct {
		name, source string
		visible      bool
	}{
		{"code", `p.write_text("k")`, true},
		{"string", `print("p.write_text(1)")`, false},
		{"one-line f-string text", `print(f"p.write_text(42)")`, false},
		{"one-line f-string field", `print(f"{p.write_text('k')}")`, true},
		{"string in a field", `print(f"{'p.write_text(1)'}")`, false},
		{"nested f-string text", `print(f"{f'p.write_text(1) {x}'}")`, false},
		{"docstring", `"""p.write_text(1)"""`, false},
		{"comment", "x = 1 # p.write_text(1)", false},
		{"bytes", `b"p.write_text(1)"`, false},
		{"unclosed string", `print("p.write_text(1)`, true},
		// Format spec text is literal; a nested field and the expression run.
		{"one-line format spec text", `print(f"{x:p.write_text(42)}")`, false},
		{"format spec text after a conversion", `print(f"{x!s:p.write_text(42)}")`, false},
		{"format spec text beside a nested field", `print(f"{x:>{w}p.write_text(42)}")`, false},
		{"nested format spec field", `print(f"{x:{p.write_text(42)}}")`, true},
		{"expression before a format spec", `print(f"{p.write_text(42):>10}")`, true},
		{"expression before a conversion", `print(f"{p.write_text(42)!r}")`, true},
		{"inequality in a field", `print(f"{p.write_text(42) != 1}")`, true},
	} {
		masked := MaskPythonStrings(tc.source)
		if len(masked) != len(tc.source) {
			t.Fatalf("%s: masked length %d, want %d", tc.name, len(masked), len(tc.source))
		}
		if got := strings.Contains(masked, write); got != tc.visible {
			t.Errorf("%s: %q masked to %q: write visible=%t, want %t", tc.name, tc.source, masked, got, tc.visible)
		}
	}
}

// Only the expressions of f-string fields are code: the braces, a conversion,
// a self-documenting "=" and format spec text are blanked.
func TestMaskPythonStringsFieldExpressions(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{`f"{x:>{w}}"`, `f  x   w   `},
		{`f"{p=}"`, `f  p   `},
		{`f"{p = !r}"`, `f  p       `},
		{`f"{p!r}"`, `f  p    `},
		{`f"{a != b}"`, `f  a != b  `},
		{`f"{a == b}"`, `f  a == b  `},
		{`f"{x!r:{w}}"`, `f  x    w   `},
		{`f"{d['k']=}"`, `f  d[   ]   `},
	} {
		if got := MaskPythonStrings(tc.source); got != tc.want {
			t.Errorf("MaskPythonStrings(%q) = %q, want %q", tc.source, got, tc.want)
		}
	}
}

// A path a write call acts on counts wherever the call is spelled outside a
// comment or a triple-quoted string: in code, an f-string field, or the text
// of a one-line string or f-string. Whether string text runs depends on the
// modules the script loads, and the import path that supplies them belongs
// to whoever runs the script later, not to the scan.
func TestPythonPathWriteMatchCountsStringText(t *testing.T) {
	rule := regexp.MustCompile(`authorized_keys`)
	for _, tc := range []struct {
		name, source string
		want         bool
	}{
		{"assigned then written", "from pathlib import Path\np = Path.home() / \".ssh\" / \"authorized_keys\"\np.write_text(\"k\")\n", true},
		{"open append", "open('/home/a/.ssh/authorized_keys', 'a').write('k')\n", true},
		{"f-string field open", "print(f\"{open('/home/a/.ssh/authorized_keys', 'a')}\")\n", true},
		{"exec of a string", "exec(\"open('/home/a/.ssh/authorized_keys', 'a').write('k')\")\n", true},
		{"f-string text", "p = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(f\"p.write_text(42)\")\n", true},
		{"string text", "p = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(\"p.write_text(42)\")\n", true},
		{"string text beside an import", "from pathlib import Path\np = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(\"p.write_text(42)\")\n", true},
		{"string text beside a preloaded import", "import os\np = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(\"p.write_text(42)\")\n", true},
		{"printed open", "print(\"open('/home/a/.ssh/authorized_keys', 'a')\")\n", true},
		{"printed Path write", "print(\"Path('/home/a/.ssh/authorized_keys').write_text('k')\")\n", true},
		{"format spec text", "p = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(f\"{1:p.write_text(42)}\")\n", true},
		{"printed open beside an ordinary variable", "source = 1\nprint(\"open('/home/a/.ssh/authorized_keys', 'a')\")\n", true},
		{"read", "open('/home/a/.ssh/authorized_keys').read()\n", false},
		{"mention", "KEYS = '/home/a/.ssh/authorized_keys'\nprint(KEYS)\n", false},
	} {
		if got := pythonPathWriteMatch(rule, tc.source) != nil; got != tc.want {
			t.Errorf("%s: pythonPathWriteMatch(%q) = %t, want %t", tc.name, tc.source, got, tc.want)
		}
	}
}

// The scan of a script finds a write spelled in string text even when the
// gateway's own environment is clean and nothing sits beside the script: the
// PYTHONPATH of whoever runs it may supply a module that runs the text.
func TestArtifactPythonStringTextWriteNeedsNoLocalModule(t *testing.T) {
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", "")
	pack := &RulePack{RuleFiles: []*RulesFileYAML{{
		Category: "persistence",
		Rules: []RuleDefYAML{{
			ID: "SSH-KEYS", Pattern: `authorized_keys`, Title: "authorized keys write",
			Severity: "HIGH", Confidence: 0.9,
			Expression: "f.paths.exists(p, p.access == defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_WRITE)",
		}},
	}}}
	dir := t.TempDir()
	script := "import json\np = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(\"p.write_text(42)\")\n"
	writer := filepath.Join(dir, "writer.py")
	if err := os.WriteFile(writer, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, writer} {
		findings, err := pack.ScanArtifact(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 1 {
			t.Errorf("ScanArtifact(%s) = %+v, want the write", path, findings)
		}
	}
}
