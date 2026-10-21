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
// order; the user's other hooks are not. Only the event and the launcher are
// described: a command's arguments (here a synthetic credential) never reach
// the description that goes into the uninstall result and lifecycle log.
func TestWindowsClaudeHooksNamingDefenseClawDescribesLeftoversWithoutArguments(t *testing.T) {
	const secret = "SYNTHETIC-B13-ARGUMENT-VALUE"
	raw := []byte(`{"hooks":{
		"Stop":[{"hooks":[{"command":"powershell -File C:\\Users\\alice\\hooks\\notify.ps1 --token ` + secret + `"}]}],
		"PreToolUse":[{"matcher":"Bash","hooks":[
			{"command":"& 'C:\\Users\\alice\\.local\\bin\\DefenseClaw-Hook.exe' hook --api-key ` + secret + `"},
			{"command":"C:\\tools\\lint.exe"}]}],
		"PostToolUse":[{"hooks":[{"command":"C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe hook --password=` + secret + `"}]}],
		"Odd key ` + secret + `":[{"hooks":[{"command":"wrap.cmd defenseclaw-gateway.exe"}]}]}}`)
	got, err := windowsClaudeHooksNamingDefenseClaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"an unrecognized hook event: a hook command naming defenseclaw-gateway (arguments not shown)",
		"PostToolUse: a hook command naming defenseclaw.exe (arguments not shown)",
		"PreToolUse: a hook command naming defenseclaw-hook (arguments not shown)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("leftovers = %q, want %q", got, want)
	}
	for _, line := range got {
		if strings.Contains(line, secret) || strings.Contains(line, `C:\`) {
			t.Fatalf("a leftover description repeats the command: %q", line)
		}
	}
	for _, clean := range []string{`{"model":"sonnet"}`, `{"hooks":{"Stop":[{"hooks":[{"command":"notify.exe"}]}]}}`} {
		if got, err := windowsClaudeHooksNamingDefenseClaw([]byte(clean)); err != nil || len(got) != 0 {
			t.Fatalf("%s: leftovers = %q (%v), want none", clean, got, err)
		}
	}
	// A file that cannot be inspected is an error, never "no leftovers".
	for _, unreadable := range []string{`not json`, `[]`, `null`} {
		if got, err := windowsClaudeHooksNamingDefenseClaw([]byte(unreadable)); err == nil {
			t.Fatalf("%s: leftovers = %q, want an error", unreadable, got)
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
