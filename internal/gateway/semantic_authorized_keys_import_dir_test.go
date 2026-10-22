// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The gateway looks at the directory a python -c program imports from only
// when it sees the filesystem the command runs in. A sandbox's or a guest's
// directory, or a relative one, is not known, so a standard-library import
// there keeps the program's strings (and its write proof) whole.
func TestTrustedPythonImportDirNeedsTheCommandsFilesystem(t *testing.T) {
	dir := t.TempDir()
	facts := actionfacts.Facts{CWD: dir}
	for _, tc := range []struct {
		name    string
		request trustedActionRequest
		facts   actionfacts.Facts
		want    string
	}{
		{"host", trustedActionRequest{}, facts, dir},
		{"sandbox", trustedActionRequest{SkipLocalFilesystemResolution: true}, facts, ""},
		{"sandbox guest", trustedActionRequest{SandboxGuestCWD: "/sandbox"}, facts, ""},
		{"relative", trustedActionRequest{}, actionfacts.Facts{CWD: filepath.Join("repo", "src")}, ""},
		{"unknown", trustedActionRequest{}, actionfacts.Facts{}, ""},
	} {
		if got := trustedPythonImportDir(tc.request, tc.facts); got != tc.want {
			t.Errorf("%s: trustedPythonImportDir = %q, want %q", tc.name, got, tc.want)
		}
	}
	// With no directory to look at, an ordinary import keeps a docstring
	// whole; in a clean one it is inert.
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", "")
	const code = `"""p.write_text("k")"""; from pathlib import Path`
	if text, _ := trustedPythonExecutedViews(code, "", false); text != code {
		t.Errorf("unknown directory: text view %q, want the code whole", text)
	}
	if text, _ := trustedPythonExecutedViews(code, dir, false); text == code {
		t.Error("clean directory: the docstring still counts")
	}
	if text, _ := trustedPythonExecutedViews(code, dir, true); text != code {
		t.Errorf("PYTHONPATH on the command: text view %q, want the code whole", text)
	}
	// sys under another name moves the import path, and a program with no
	// import statement still imports (a codec lookup): the docstring counts.
	for _, tc := range []struct{ code, dir string }{
		{`"""p.write_text("k")"""` + "\nimport sys; s = sys; s.path.insert(0, '/tmp/shadow'); import json", dir},
		{`"""p.write_text("k")"""` + "\nimport os; os.sys.meta_path.clear(); import json", dir},
		{`"""p.write_text("k")"""` + "\n'a'.encode('idna')", ""},
	} {
		if text, _ := trustedPythonExecutedViews(tc.code, tc.dir, false); text != tc.code {
			t.Errorf("trustedPythonExecutedViews(%q, %q): text view %q, want the code whole", tc.code, tc.dir, text)
		}
	}
}
