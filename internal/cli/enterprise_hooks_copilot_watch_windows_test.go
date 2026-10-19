//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// A Copilot row's VS Code Local hook file was in no watch list, so its
// removal waited for the interval pass (GAP-0664).
func TestEnterpriseHookPlatformWatchFilesNamesTheCopilotVSCodeHookFile(t *testing.T) {
	home := t.TempDir()
	want := filepath.Join(home, ".copilot", "hooks", "defenseclaw-vscode.json")
	dirs, files := enterpriseHookPlatformWatchFiles("copilot", home)
	if len(dirs) != 0 || len(files) != 1 || files[0] != want {
		t.Fatalf("without the hooks folder: dirs %q files %q, want no folder and %s", dirs, files, want)
	}
	if err := os.MkdirAll(filepath.Dir(want), 0o700); err != nil {
		t.Fatal(err)
	}
	dirs, files = enterpriseHookPlatformWatchFiles("Copilot", home)
	if len(dirs) != 1 || dirs[0] != filepath.Dir(want) || len(files) != 1 || files[0] != want {
		t.Fatalf("with the hooks folder: dirs %q files %q", dirs, files)
	}
	for _, other := range []string{"codex", "claudecode", "cursor", "hermes"} {
		if dirs, files := enterpriseHookPlatformWatchFiles(other, home); len(dirs)+len(files) != 0 {
			t.Fatalf("%s: dirs %q files %q, want none", other, dirs, files)
		}
	}
}
