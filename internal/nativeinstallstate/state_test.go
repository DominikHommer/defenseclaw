// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package nativeinstallstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fixtureState(t *testing.T) (State, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "DefenseClaw")
	bin := filepath.Join(root, "bin")
	installer := filepath.Join(root, "installer")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(installer, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(bin, "defenseclaw.exe")
	if err := os.WriteFile(executable, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}
	state := State{
		SchemaVersion:        1,
		InstallKind:          "native-windows-exe",
		InstallScope:         "user",
		InstallRoot:          root,
		CommandDir:           bin,
		DataRoot:             filepath.Join(t.TempDir(), ".defenseclaw"),
		Runtime:              filepath.Join(root, "runtime", "python"),
		CodexHome:            filepath.Join(t.TempDir(), "codex-home"),
		ClaudeConfigDir:      filepath.Join(t.TempDir(), "claude-home"),
		CopilotHome:          filepath.Join(t.TempDir(), "copilot-home"),
		CursorHome:           filepath.Join(t.TempDir(), "cursor-home"),
		AntigravityConfigDir: filepath.Join(t.TempDir(), ".gemini", "config"),
		OpenCodeConfigDir:    filepath.Join(t.TempDir(), "opencode-home"),
		HermesHome:           filepath.Join(t.TempDir(), "hermes-home"),
	}
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installer, "install-state.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return state, executable
}

func TestLoadAtRejectsRelocatedOrMalformedState(t *testing.T) {
	state, executable := fixtureState(t)
	state.InstallRoot = filepath.Join(t.TempDir(), "foreign")
	body, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(filepath.Dir(filepath.Dir(executable)), "installer", "install-state.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAt(executable, filepath.Dir(filepath.Dir(executable))); err == nil {
		t.Fatal("relocated state was accepted")
	}
}
