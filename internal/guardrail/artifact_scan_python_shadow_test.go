// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// An import the program never uses still runs the module it loads, and the
// modules that module imports in turn; for python -c the first place Python
// looks is the working directory. A subprocess.py, helper.py, or a re.py that
// json and pathlib import, there can run the program's docstring, so the
// docstring is not inert. With nothing in that directory the standard
// library runs no string. The interpreter shows the write happen or not; the
// scan, given the directory, must agree, and without it must keep the
// docstring whole.
func TestShadowedModuleRunsTheMainDocstring(t *testing.T) {
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", "")
	const docstring = `"""open("written-by-docstring", "w").write("x")"""`
	for _, module := range []string{"subprocess", "helper", "json"} {
		code := docstring + "\nimport " + module + "\n"
		if !PythonStringsMayRun(MaskPythonStrings(code), "") {
			t.Errorf("PythonStringsMayRun(%q, unknown dir) = false: a shadowed %s.py runs the docstring", code, module)
		}
	}
	// A preloaded module is never read from the working directory.
	preloaded := docstring + "\nimport os\n"
	if PythonStringsMayRun(MaskPythonStrings(preloaded), "") {
		t.Errorf("PythonStringsMayRun(%q) = true, want false", preloaded)
	}
	python, err := exec.LookPath("python3")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("no python3 to show the shadowed import run")
	}
	for _, tc := range []struct {
		shadow, imports string
		ran             bool
	}{
		{"subprocess", "import subprocess", true},
		{"helper", "import helper", true},
		{"os", "import os", false},
		{"re", "import json", true},
		{"re", "from pathlib import Path", true},
		{"fnmatch", "from pathlib import Path", true},
		{"", "import subprocess", false},
		{"", "import json", false},
		{"", "from pathlib import Path", false},
	} {
		dir := t.TempDir()
		if tc.shadow != "" {
			shadow := "import sys\nexec(sys.modules['__main__'].__doc__)\n"
			if err := os.WriteFile(filepath.Join(dir, tc.shadow+".py"), []byte(shadow), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		code := docstring + "\n" + tc.imports + "\n"
		mayRun := PythonStringsMayRun(MaskPythonStrings(code), dir)
		cmd := exec.Command(python, "-c", code)
		cmd.Dir = dir
		cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool {
			return strings.HasPrefix(kv, "PYTHON")
		})
		// A shadow may break the import after it ran; the standard library
		// alone must run clean.
		if out, err := cmd.CombinedOutput(); err != nil && tc.shadow == "" {
			t.Fatalf("python3 -c %q beside %q: %v: %s", tc.imports, tc.shadow, err, out)
		}
		_, err := os.Stat(filepath.Join(dir, "written-by-docstring"))
		if ran := err == nil; ran != tc.ran {
			t.Errorf("%s beside %q.py ran the docstring = %t, want %t", tc.imports, tc.shadow, ran, tc.ran)
		}
		if mayRun != tc.ran {
			t.Errorf("PythonStringsMayRun(%q, dir with %q.py) = %t, the interpreter ran it = %t", code, tc.shadow, mayRun, tc.ran)
		}
	}
}
