// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWindowsUninstallRemovesOnlyExactClaudeLauncher(t *testing.T) {
	const launcher = `C:\Users\alice\.local\bin\defenseclaw-hook.exe`
	raw := []byte(`{"model":"sonnet","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"C:\\Users\\alice\\.local\\bin\\defenseclaw-hook.exe","args":["hook"]},{"type":"command","command":"C:\\Other\\defenseclaw-hook.exe"},{"type":"command","command":"C:\\Users\\bob\\.local\\bin\\defenseclaw-hook.exe"}]},{"hooks":[{"command":"C:\\Users\\alice\\.local\\bin\\defenseclaw-hook.exe --other"}]}]}}`)
	out, removed, err := removeWindowsManagedClaudeCommands(raw, launcher)
	if err != nil || removed != 2 {
		t.Fatalf("removed=%d error=%v: %s", removed, err, out)
	}
	var settings map[string]any
	if err := json.Unmarshal(out, &settings); err != nil || settings["model"] != "sonnet" {
		t.Fatalf("settings changed: %s (%v)", out, err)
	}
	if strings.Contains(string(out), `alice\\.local`) || !strings.Contains(string(out), `Other\\defenseclaw-hook.exe`) ||
		!strings.Contains(string(out), `bob\\.local`) {
		t.Fatalf("foreign hooks were changed or owned hooks survived: %s", out)
	}
	again, count, err := removeWindowsManagedClaudeCommands(out, launcher)
	if err != nil || count != 0 || string(again) != string(out) {
		t.Fatalf("cleanup is not idempotent: %d %v", count, err)
	}
}

// #1286: after the exact per-user hook is removed, every command that still
// names a DefenseClaw launcher is found, whatever its shape, in a stable
// order; the user's other hooks are not.
func TestWindowsClaudeCommandsNamingDefenseClawFindsLeftovers(t *testing.T) {
	raw := []byte(`{"hooks":{
		"Stop":[{"hooks":[{"command":"powershell -File C:\\Users\\alice\\hooks\\notify.ps1"}]}],
		"PreToolUse":[{"matcher":"Bash","hooks":[
			{"command":"& 'C:\\Users\\alice\\.local\\bin\\DefenseClaw-Hook.exe' hook --connector claudecode"},
			{"command":"C:\\tools\\lint.exe"}]}],
		"PostToolUse":[{"hooks":[{"command":"C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe hook"}]}]}}`)
	got := windowsClaudeCommandsNamingDefenseClaw(raw)
	want := []string{
		`PostToolUse: C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe hook`,
		`PreToolUse: & 'C:\Users\alice\.local\bin\DefenseClaw-Hook.exe' hook --connector claudecode`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("leftovers = %q, want %q", got, want)
	}
	for _, clean := range []string{`{"model":"sonnet"}`, `{"hooks":{"Stop":[{"hooks":[{"command":"notify.exe"}]}]}}`, `not json`} {
		if got := windowsClaudeCommandsNamingDefenseClaw([]byte(clean)); len(got) != 0 {
			t.Fatalf("%s: leftovers = %q, want none", clean, got)
		}
	}
}

func TestWindowsManagedHookCommandRequiresExactLauncherBoundary(t *testing.T) {
	const launcher = `C:\Users\Alice Doe\.local\bin\defenseclaw-hook.exe`
	for _, command := range []string{
		`"C:\Users\Alice Doe\.local\bin\defenseclaw-hook.exe"`,
		`& 'C:\Users\Alice Doe\.local\bin\defenseclaw-hook.exe' hook --connector claudecode`,
	} {
		if !windowsManagedHookCommandIs(command, launcher) {
			t.Fatalf("owned launcher was missed: %q", command)
		}
	}
	for _, command := range []string{
		`C:\Users\Alice Doe\.local\bin\defenseclaw-hook.exe.old`,
		`C:\Other\defenseclaw-hook.exe`,
		`"C:\Users\Alice Doe\.local\bin\defenseclaw-hook.exe.old" hook`,
	} {
		if windowsManagedHookCommandIs(command, launcher) {
			t.Fatalf("foreign command was claimed: %q", command)
		}
	}
}
