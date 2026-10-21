// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
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

// Code may run a string only through a sink it names in code; an import no
// name of which is used runs nothing.
func TestPythonStringsMayRun(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   bool
	}{
		{`import subprocess; """x"""; print("ok")`, false},
		{"import subprocess as sp, ctypes\nfrom os import system as run, popen\nprint('ok')", false},
		{`if x: import subprocess`, false},
		{"from importlib import (util,\n    machinery)", false},
		{`print("exec subprocess")`, false},
		{`# exec`, false},
		{`f"exec {x}"`, false},
		{`import subprocess; subprocess.run(["true"])`, true},
		{`import subprocess as sp; sp.run(["true"])`, true},
		{`from subprocess import run; f = run`, true},
		{`from subprocess import *`, true},
		{`from subprocess import run,`, true},
		{`exec("x")`, true},
		{`f"{eval('x')}"`, true},
		{`import os; os.posix_spawn("/bin/true", [], {})`, true},
		{`import timeit; timeit.timeit("x")`, true},
		{`exec(__doc__)`, true},
		{`print(__doc__)`, true},
		{`import sys; print(sys.orig_argv)`, true},
		{`open("m.py", "w").write("x"); import m`, true},
		{`import sys; sys.modules["subprocess"]`, true},
		{`().__class__.__base__.__subclasses__()`, true},
		{`import pty`, false},
		{`import pty; pty.spawn("sh")`, true},
	} {
		if got := PythonStringsMayRun(MaskPythonStrings(tc.source)); got != tc.want {
			t.Errorf("PythonStringsMayRun(%q) = %t, want %t", tc.source, got, tc.want)
		}
	}
}

// A write call spelled in a string, or in the literal text of an f-string,
// writes nothing; a path in a string that a call in code writes still does.
func TestPythonPathWriteMatchNeedsAWriteCallInCode(t *testing.T) {
	rule := regexp.MustCompile(`authorized_keys`)
	for _, tc := range []struct {
		name, source string
		want         bool
	}{
		{"assigned then written", "from pathlib import Path\np = Path.home() / \".ssh\" / \"authorized_keys\"\np.write_text(\"k\")\n", true},
		{"open append", "open('/home/a/.ssh/authorized_keys', 'a').write('k')\n", true},
		{"f-string field open", "print(f\"{open('/home/a/.ssh/authorized_keys', 'a')}\")\n", true},
		{"exec of a string", "exec(\"open('/home/a/.ssh/authorized_keys', 'a').write('k')\")\n", true},
		{"f-string text", "from pathlib import Path\np = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(f\"p.write_text(42)\")\n", false},
		{"string text", "from pathlib import Path\np = Path.home() / \".ssh\" / \"authorized_keys\"\nprint(\"p.write_text(42)\")\n", false},
		{"printed open", "print(\"open('/home/a/.ssh/authorized_keys', 'a')\")\n", false},
		{"printed Path write", "print(\"Path('/home/a/.ssh/authorized_keys').write_text('k')\")\n", false},
	} {
		if got := pythonPathWriteMatch(rule, tc.source) != nil; got != tc.want {
			t.Errorf("%s: pythonPathWriteMatch(%q) = %t, want %t", tc.name, tc.source, got, tc.want)
		}
	}
}
