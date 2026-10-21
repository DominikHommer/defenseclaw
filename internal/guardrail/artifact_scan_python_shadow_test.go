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

// An import the program never uses still runs the module it loads, and for
// python -c the first place Python looks is the working directory. A
// subprocess.py (or any other name but a preloaded module) there can run the
// program's docstring, so the docstring is not inert. The interpreter shows
// the write happen; the scan must keep the docstring whole.
func TestShadowedModuleRunsTheMainDocstring(t *testing.T) {
	for _, module := range []string{"subprocess", "helper", "json"} {
		code := `"""open("written-by-docstring", "w").write("x")"""` + "\nimport " + module + "\n"
		if !PythonStringsMayRun(MaskPythonStrings(code)) {
			t.Errorf("PythonStringsMayRun(%q) = false: a shadowed %s.py runs the docstring", code, module)
		}
	}
	// A preloaded module is never read from the working directory.
	preloaded := `"""open("written-by-docstring", "w").write("x")"""` + "\nimport os\n"
	if PythonStringsMayRun(MaskPythonStrings(preloaded)) {
		t.Errorf("PythonStringsMayRun(%q) = true, want false", preloaded)
	}
	python, err := exec.LookPath("python3")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("no python3 to show the shadowed import run")
	}
	for _, module := range []string{"subprocess", "helper", "os"} {
		dir := t.TempDir()
		shadow := "import sys\nexec(sys.modules['__main__'].__doc__)\n"
		if err := os.WriteFile(filepath.Join(dir, module+".py"), []byte(shadow), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(python, "-c", `"""open("written-by-docstring", "w").write("x")"""`+"\nimport "+module+"\n")
		cmd.Dir = dir
		cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool {
			return strings.HasPrefix(kv, "PYTHON")
		})
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("python3 -c with %s.py: %v: %s", module, err, out)
		}
		_, err := os.Stat(filepath.Join(dir, "written-by-docstring"))
		if ran := err == nil; ran != (module != "os") {
			t.Errorf("import %s ran the docstring = %t, want %t", module, ran, module != "os")
		}
	}
}
