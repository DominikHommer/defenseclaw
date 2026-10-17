// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// stopCurlStub answers every request with DC_STOP_REPLY: "exit:N" fails the
// transfer with curl exit N, "STATUS|BODY" answers that status and body.
const stopCurlStub = `#!/bin/sh
case "$DC_STOP_REPLY" in
  exit:*) exit "${DC_STOP_REPLY#exit:}" ;;
esac
printf '%s\n%s\n' "${DC_STOP_REPLY#*|}" "${DC_STOP_REPLY%%|*}"
`

const stopEventNotBlockedLead = "DefenseClaw is not blocking the "

// The shell hooks use the native runner's stop set (#1140); OpenCode's
// stop events reach only the native runner (its plugin calls the binary).
func TestShellFailedStopEventMatchesTheNativeStopSet(t *testing.T) {
	type probe struct{ connector, event, payload, env string }
	var stops, others []probe
	for _, connector := range []string{"claudecode", "codex", "copilot", "cursor", "devin", "kiro"} {
		events := hookexec.NeutralLifecycleEvents(connector)
		if len(events) == 0 {
			t.Fatalf("%s has no native stop set", connector)
		}
		for _, event := range events {
			stops = append(stops, probe{connector: connector, event: event})
			stops = append(stops, probe{connector: connector, payload: `{"hook_event_name":"` + event + `"}`})
			// The Secure Client profile keeps its results.
			others = append(others, probe{connector: connector, event: event, env: "_DC_SECURE_CLIENT_HOOK=1"})
		}
	}
	stops = append(stops, probe{connector: "cursor", event: "SESSIONEND"}, probe{connector: "devin", payload: `{"event":"Stop"}`})
	others = append(others,
		probe{connector: "codex", event: "PreToolUse"}, probe{connector: "codex", event: "stop"},
		probe{connector: "claudecode", event: "UserPromptSubmit"}, probe{connector: "kiro", event: "PostToolUse"},
		probe{connector: "cursor", event: "beforeShellExecution"}, probe{connector: "copilot", event: "preToolUse"},
		probe{connector: "opencode", event: "session.idle"}, probe{connector: "hermes", event: "on_session_end"},
		probe{connector: "amp", event: "Stop"}, probe{connector: "claudecode"},
		probe{connector: "claudecode", payload: `{}`}, probe{connector: "claudecode", payload: `not json`},
		probe{connector: "devin", payload: `{"hook_event_name":"Stop","event":"PreToolUse"}`},
	)
	check := func(p probe, want bool) {
		t.Helper()
		cmd := exec.Command("bash", "-c", `set -euo pipefail; . "$1"; defenseclaw_failed_stop_event "$2" "$3" "$4"`,
			"probe", filepath.Join("hooks", "_hardening.sh"), p.connector, p.event, p.payload)
		cmd.Env = append(sanitizedTestEnv(), p.env)
		err := cmd.Run()
		if got := err == nil; got != want {
			t.Errorf("%+v: stop event = %v, want %v (%v)", p, got, want, err)
		}
	}
	for _, p := range stops {
		check(p, true)
	}
	for _, p := range others {
		check(p, false)
	}
}

type stopHookRun struct {
	code   int
	stdout string
	stderr string
	log    string
}

// runPerUserHookForStop runs a rendered per-user hook whose gateway answers
// reply, with automatic gateway start off.
func runPerUserHookForStop(t *testing.T, c Connector, script string, args []string, stdin, reply string, extraEnv ...string) stopHookRun {
	t.Helper()
	hooksDir := t.TempDir()
	if err := WriteHookScriptsForConnectorObject(hooksDir, freeAPIAddr(t), "stop-scoped-token", c); err != nil {
		t.Fatalf("write hooks: %v", err)
	}
	stubDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stubDir, "curl"), []byte(stopCurlStub), 0o755); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hooksDir, script)
	bakeHookPathForTest(t, hookPath, stubDir+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	env := make([]string, 0, 64)
	for _, entry := range sanitizedTestEnv() {
		if name, _, _ := strings.Cut(entry, "="); name != "HOME" {
			env = append(env, entry)
		}
	}
	env = append(env, "HOME="+home, "DEFENSECLAW_HOME="+dataDir, "DEFENSECLAW_GATEWAY_AUTOSTART=0", "DC_STOP_REPLY="+reply)
	env = append(env, extraEnv...)
	if strings.Contains(strings.Join(extraEnv, " "), "DC_TEST_NO_TOKEN=1") {
		tokens, _ := filepath.Glob(filepath.Join(hooksDir, "*.token"))
		dotTokens, _ := filepath.Glob(filepath.Join(hooksDir, ".*token"))
		for _, path := range append(tokens, dotTokens...) {
			_ = os.Remove(path)
		}
	}
	cmd := exec.Command("bash", append([]string{hookPath}, args...)...)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	log, _ := os.ReadFile(filepath.Join(dataDir, "logs", "hook-failures.jsonl"))
	return stopHookRun{code: exitCodeOf(err), stdout: stdout.String(), stderr: stderr.String(), log: string(log)}
}

// #1140 on the per-user shell hooks (Linux and macOS): with fail mode
// closed, a stop event whose gateway is down, answers 5xx or answers
// something unusable gets the neutral allow and is logged as fail mode
// open, so Codex no longer retries a blocked Stop on every model turn. A
// tool call stays blocked, and the fail-open profile is unchanged.
func TestPerUserShellHooksLetAFailedStopEventThrough(t *testing.T) {
	codexArgs := func(event string) []string { return codexBoundShellHookArgsForTest(t, "codex-hook.sh", event)[1:] }
	stops := []struct {
		name      string
		c         Connector
		script    string
		args      []string
		stdin     string
		stdout    string
		noTokenOK bool
	}{
		{"codex Stop", NewCodexConnector(), "codex-hook.sh", codexArgs("Stop"), `{"hook_event_name":"Stop","session_id":"s1"}`, "", true},
		{"codex SubagentStop", NewCodexConnector(), "codex-hook.sh", codexArgs("SubagentStop"), `{"hook_event_name":"SubagentStop","session_id":"s1"}`, "", true},
		{"claude Stop", NewClaudeCodeConnector(), "claude-code-hook.sh", nil, `{"hook_event_name":"Stop","session_id":"s1","stop_hook_active":true}`, "", true},
		{"claude SessionEnd", NewClaudeCodeConnector(), "claude-code-hook.sh", nil, `{"hook_event_name":"SessionEnd","session_id":"s1"}`, "", true},
		{"cursor stop", NewCursorConnector(), "cursor-hook.sh", nil, `{"hook_event_name":"stop","conversation_id":"c1","status":"completed"}`, "{}", true},
		{"devin Stop", NewDevinConnector(), "devin-hook.sh", nil, `{"hook_event_name":"Stop","session_id":"s1"}`, "", false},
		{"kiro Stop", NewKiroConnector(), "kiro-hook.sh", nil, `{"hook_event_name":"Stop","session_id":"s1"}`, "", false},
	}
	replies := map[string]string{"gateway down": "exit:7", "gateway 502": `502|{}`, "unusable answer": `200|<html>proxy</html>`, "gateway 401": `401|{"error":"unauthorized"}`}
	for _, tc := range stops {
		for name, reply := range replies {
			run := runPerUserHookForStop(t, tc.c, tc.script, tc.args, tc.stdin, reply, "DEFENSECLAW_FAIL_MODE=closed")
			if run.code != 0 || strings.TrimSpace(run.stdout) != tc.stdout || !strings.Contains(run.stderr, stopEventNotBlockedLead) {
				t.Errorf("%s, %s: want the neutral allow %q, got exit %d stdout=%q stderr=%q", tc.name, name, tc.stdout, run.code, run.stdout, run.stderr)
			}
			if !strings.Contains(run.log, `"fail_mode":"open"`) || strings.Contains(run.log, `"fail_mode":"closed"`) {
				t.Errorf("%s, %s: want one failure logged as fail mode open: %s", tc.name, name, run.log)
			}
		}
		if tc.noTokenOK {
			run := runPerUserHookForStop(t, tc.c, tc.script, tc.args, tc.stdin, `200|{"action":"allow"}`, "DEFENSECLAW_FAIL_MODE=closed", "DC_TEST_NO_TOKEN=1")
			if run.code != 0 || strings.TrimSpace(run.stdout) != tc.stdout || !strings.Contains(run.stderr, stopEventNotBlockedLead) {
				t.Errorf("%s, missing token: want the neutral allow, got exit %d stdout=%q stderr=%q", tc.name, run.code, run.stdout, run.stderr)
			}
		}
		open := runPerUserHookForStop(t, tc.c, tc.script, tc.args, tc.stdin, "exit:7", "DEFENSECLAW_FAIL_MODE=open")
		if open.code != 0 || strings.Contains(open.stderr, stopEventNotBlockedLead) {
			t.Errorf("%s, fail mode open: exit %d stderr=%q, want the unchanged fail-open allow", tc.name, open.code, open.stderr)
		}
	}

	codexTool := runPerUserHookForStop(t, NewCodexConnector(), "codex-hook.sh", codexArgs("PreToolUse"), codexPreToolUse, "exit:7", "DEFENSECLAW_FAIL_MODE=closed")
	if codexTool.code != 2 || strings.Contains(codexTool.stderr, stopEventNotBlockedLead) {
		t.Errorf("codex PreToolUse: exit %d stderr=%q, want the fail-closed block", codexTool.code, codexTool.stderr)
	}
	codexPrompt := runPerUserHookForStop(t, NewCodexConnector(), "codex-hook.sh", codexArgs("UserPromptSubmit"), `{"hook_event_name":"UserPromptSubmit","prompt":"hi"}`, `502|{}`, "DEFENSECLAW_FAIL_MODE=closed")
	if codexPrompt.code != 2 {
		t.Errorf("codex UserPromptSubmit: exit %d stderr=%q, want the fail-closed block", codexPrompt.code, codexPrompt.stderr)
	}
	claudeTool := runPerUserHookForStop(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, claudePreToolUse, "exit:7", "DEFENSECLAW_FAIL_MODE=closed")
	if !strings.Contains(claudeTool.stdout, `"permissionDecision":"deny"`) && claudeTool.code != 2 {
		t.Errorf("claude PreToolUse: exit %d stdout=%q, want the fail-closed deny", claudeTool.code, claudeTool.stdout)
	}
	// A payload whose two event fields disagree names no stop event.
	devinMixed := runPerUserHookForStop(t, NewDevinConnector(), "devin-hook.sh", nil, `{"hook_event_name":"Stop","event":"PreToolUse"}`, "exit:7", "DEFENSECLAW_FAIL_MODE=closed")
	if devinMixed.code != 2 {
		t.Errorf("devin mixed events: exit %d stderr=%q, want the fail-closed block", devinMixed.code, devinMixed.stderr)
	}
}

// #1140 in the OpenShell sandbox hooks, which always fail closed: the live
// Codex sandbox repeated its blocked Stop 33 times while the gateway was
// down. A stop event now gets the neutral allow on every failure the
// ingress or the relay can produce; tool calls stay blocked
// (TestSandboxHooksFailClosed).
func TestSandboxHooksLetAFailedStopEventThrough(t *testing.T) {
	cases := []struct {
		provider SandboxArtifactProvider
		version  string
		script   string
		args     []string
		stdin    string
		stdout   string
	}{
		{&ClaudeCodeConnector{}, "2.1.156", "claude-code-hook.sh", nil, `{"hook_event_name":"Stop","session_id":"s1","stop_hook_active":false}`, ""},
		{&CodexConnector{}, "0.146.0", "codex-hook.sh", []string{"--event", "Stop", "--hook-contract", "codex-hooks-v4"}, `{"hook_event_name":"Stop","session_id":"s1"}`, ""},
		{NewCopilotConnector(), "1.0.88", "copilot-hook.sh", []string{"--event", "agentStop"}, `{"sessionId":"s1","timestamp":1790483549431,"cwd":"/work/proj"}`, ""},
		{NewCursorConnector(), "2026.07.23-e383d2b", "cursor-hook.sh", nil, `{"hook_event_name":"stop","conversation_id":"c1","status":"completed"}`, "{}"},
		{NewKiroConnector(), "2.24.1", "kiro-hook.sh", nil, `{"hook_event_name":"Stop","session_id":"s1"}`, ""},
		{NewDevinConnector(), "3000.4.25", "devin-hook.sh", nil, `{"hook_event_name":"Stop","session_id":"s1"}`, ""},
	}
	replies := map[string][]string{
		"ingress-down": {"exit:7", "exit:7"},
		"relay-500":    {`500|placeholder did not resolve`},
		"unauthorized": {`401|{"error":"bad token"}`},
		"not-json":     {`200|<html>proxy</html>`},
		"no-action":    {`200|{"ok":true}`},
	}
	for _, tc := range cases {
		h := newSandboxHookHarness(t, tc.provider, tc.version)
		for name, responses := range replies {
			run := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, map[string]string{SandboxTokenEnv: "tok"}, responses)
			if run.exitCode != 0 || strings.TrimSpace(run.stdout) != tc.stdout || !strings.Contains(run.stderr, stopEventNotBlockedLead) {
				t.Errorf("%s/%s: want the neutral allow %q, got exit %d stdout=%q stderr=%q", tc.script, name, tc.stdout, run.exitCode, run.stdout, run.stderr)
			}
		}
	}
}
