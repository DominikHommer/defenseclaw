// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// outageToolCall is one tool call each per-user shell hook answers for
// itself while its gateway is down.
type outageToolCall struct {
	script string
	args   []string
	stdin  string
}

var outageToolCalls = map[string]outageToolCall{
	"copilot": {"copilot-hook.sh", []string{"--event", "preToolUse"},
		`{"sessionId":"s1","timestamp":1790483549431,"cwd":"/work","toolName":"bash","toolArgs":{"command":"ls"}}`},
	"cursor": {"cursor-hook.sh", nil,
		`{"hook_event_name":"beforeShellExecution","conversation_id":"c1","command":"ls","cwd":"/work"}`},
	"antigravity": {"antigravity-hook.sh", []string{"PreToolUse"},
		`{"toolName":"run_command","toolInput":{"CommandLine":"ls"}}`},
}

func requireShellHookToolsForTest(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required to run the shell hooks", tool)
		}
	}
}

// closedLoopbackAddrForTest is a loopback address nothing listens on: a
// gateway that is down.
func closedLoopbackAddrForTest(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// runOutageToolCall runs the hook in dataDir/hooks for one tool call while
// the gateway is stopped (gateway.stopped: no restart wait, no cold start)
// and reports whether the agent blocks it: exit 2, or the agent's native
// denial on stdout (Copilot permissionDecision, Cursor permission,
// Antigravity decision).
func runOutageToolCall(t *testing.T, home, dataDir string, call outageToolCall) (bool, string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dataDir, "gateway.stopped"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{filepath.Join(dataDir, "hooks", call.script)}, call.args...)...)
	cmd.Stdin = strings.NewReader(call.stdin)
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "DEFENSECLAW_") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(env, "HOME="+home, "DEFENSECLAW_HOME="+dataDir, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %s: %v", call.script, err)
		}
		code = exitErr.ExitCode()
	}
	out := stdout.String()
	return code == 2 || strings.Contains(out, `"deny"`), fmt.Sprintf("exit %d stdout=%q stderr=%q", code, out, stderr.String())
}

// The owner rule (hooks fail closed everywhere except Secure Client) for the
// per-user hooks of agents without a fail-closed hook contract of their own,
// and for Cursor, whose observe registration is fail-open: with the gateway
// down, this release's Copilot, Antigravity and Cursor hooks block a tool
// call unless the config opens their outages. Before r104 W3 G3-upg the
// Copilot and Antigravity renders were lowered to open for an unset mode
// (and Copilot's script let every failure run whatever its mode), and a
// Cursor in observe rendered open.
func TestPerUserHooksBlockAToolCallWhileTheGatewayIsDown(t *testing.T) {
	requireShellHookToolsForTest(t)
	addr := closedLoopbackAddrForTest(t)
	for _, test := range []struct {
		name, connector string
		opts            SetupOpts
		block           bool
	}{
		{"copilot unset", "copilot", SetupOpts{}, true},
		{"copilot closed", "copilot", SetupOpts{HookFailMode: "closed", ConfiguredHookFailMode: "closed"}, true},
		{"copilot open", "copilot", SetupOpts{HookFailMode: "open", ConfiguredHookFailMode: "open"}, false},
		{"antigravity unset", "antigravity", SetupOpts{}, true},
		{"antigravity open", "antigravity", SetupOpts{HookFailMode: "open", ConfiguredHookFailMode: "open"}, false},
		// The gateway passes Cursor's resolved mode (open in observe) and the
		// config's own value separately.
		{"cursor observe unset", "cursor", SetupOpts{GuardrailMode: "observe", HookFailMode: "open"}, true},
		{"cursor observe open", "cursor", SetupOpts{GuardrailMode: "observe", HookFailMode: "open", ConfiguredHookFailMode: "open"}, false},
		{"cursor action open", "cursor", SetupOpts{GuardrailMode: "action", HookFailMode: "closed", ConfiguredHookFailMode: "open"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, ok := NewDefaultRegistry().Get(test.connector)
			if !ok {
				t.Fatalf("no %s connector", test.connector)
			}
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			opts := test.opts
			opts.DataDir, opts.APIAddr, opts.HookAPIToken = dataDir, addr, "outage-test-token"
			if err := WriteHookScriptsForConnectorObjectWithOpts(filepath.Join(dataDir, "hooks"), opts, conn); err != nil {
				t.Fatal(err)
			}
			blocked, detail := runOutageToolCall(t, home, dataDir, outageToolCalls[test.connector])
			if blocked != test.block {
				t.Fatalf("blocked = %v, want %v: %s", blocked, test.block, detail)
			}
			// What the hook does is what its sidecar entry records, with the
			// config as its source: the native hook and the shared shell
			// readers follow the same mode.
			want := "open"
			if test.block {
				want = "closed"
			}
			state := readHookConfigSidecarForTest(t, filepath.Join(dataDir, "hooks"))
			if state.FailModes[test.connector] != want || state.FailModeSources[test.connector] != HookFailModeSourceConfig {
				t.Fatalf("sidecar %+v, want %s from the config", state, want)
			}
		})
	}
}

// The installers run the new gateway's refresh-fail-modes before the old
// gateway stops. The hooks it refreshes are an earlier release's own scripts,
// which keep answering until the new gateway renders its own:
// testdata/released-hooks holds the per-user Copilot, Cursor (observe) and
// Antigravity hooks and the _hardening.sh they source, as 0.8.10, 1.0.0 and
// 1.0.3 rendered them for an unset fail mode. Each lets a tool call run while
// the gateway is down. After a refresh that resolves closed every one of
// them blocks it, Copilot's 1.0.x hook included (its failure functions exit 0
// whatever FAIL_MODE says); after one that resolves the operator's open they
// are left as they were.
func TestRefreshMakesReleasedHooksBlockWhileTheGatewayIsDown(t *testing.T) {
	requireShellHookToolsForTest(t)
	addr := closedLoopbackAddrForTest(t)
	for _, release := range []string{"0.8.10", "1.0.0", "1.0.3"} {
		for _, connector := range []string{"copilot", "cursor", "antigravity"} {
			for _, mode := range []string{"closed", "open"} {
				t.Run(release+"/"+connector+"/"+mode, func(t *testing.T) {
					call := outageToolCalls[connector]
					home := t.TempDir()
					dataDir := filepath.Join(home, ".defenseclaw")
					hookDir := filepath.Join(dataDir, "hooks")
					if err := os.MkdirAll(hookDir, 0o700); err != nil {
						t.Fatal(err)
					}
					for _, name := range []string{"_hardening.sh", call.script} {
						body, err := os.ReadFile(filepath.Join("testdata", "released-hooks", release, name))
						if err != nil {
							t.Fatal(err)
						}
						// The renders baked a placeholder gateway address.
						if name == call.script {
							if !bytes.Contains(body, []byte(`API_ADDR="127.0.0.1:9"`)) {
								t.Fatalf("%s %s bakes no gateway address", release, name)
							}
							body = bytes.ReplaceAll(body, []byte(`API_ADDR="127.0.0.1:9"`), []byte(`API_ADDR="`+addr+`"`))
						}
						if err := os.WriteFile(filepath.Join(hookDir, name), body, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.WriteFile(filepath.Join(hookDir, ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=outage-test-token\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					script := filepath.Join(hookDir, call.script)
					before, err := os.ReadFile(script)
					if err != nil {
						t.Fatal(err)
					}
					blockedBefore, detail := runOutageToolCall(t, home, dataDir, call)
					if blockedBefore {
						t.Fatalf("precondition: the %s hook blocks before the refresh: %s", release, detail)
					}

					if _, err := RefreshHookFailModes(hookDir, func(string) string { return mode }); err != nil {
						t.Fatal(err)
					}
					blocked, detail := runOutageToolCall(t, home, dataDir, call)
					if blocked != (mode == "closed") {
						t.Fatalf("after a refresh to %s: blocked = %v: %s", mode, blocked, detail)
					}
					if mode == "open" {
						if after, _ := os.ReadFile(script); !bytes.Equal(after, before) {
							t.Fatalf("a refresh to the operator's open changed the %s hook", release)
						}
					}
				})
			}
		}
	}
}

// TestRefreshClosesReleasedCopilotEarlyFailures runs each released Copilot
// hook, refreshed for closed mode, through every failure that happens before
// its gateway request. Copilot reads the whole stdout as one JSON document,
// so each answer must parse as exactly one object carrying the denial of the
// registered event (both denials when no reviewed event is registered) and
// nothing at all for an event that cannot block.
func TestRefreshClosesReleasedCopilotEarlyFailures(t *testing.T) {
	requireShellHookToolsForTest(t)
	failures := []struct {
		name  string
		setup func(t *testing.T, hookDir string) (dataDir string)
	}{
		{"missing helper", func(t *testing.T, hookDir string) string {
			if err := os.Remove(filepath.Join(hookDir, "_hardening.sh")); err != nil {
				t.Fatal(err)
			}
			return filepath.Dir(hookDir)
		}},
		{"broken helper", func(t *testing.T, hookDir string) string {
			if err := os.WriteFile(filepath.Join(hookDir, "_hardening.sh"), []byte("return 1\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			return filepath.Dir(hookDir)
		}},
		{"missing token", func(_ *testing.T, hookDir string) string { return filepath.Dir(hookDir) }},
		{"missing home", func(_ *testing.T, hookDir string) string {
			return filepath.Join(filepath.Dir(hookDir), "absent")
		}},
	}
	calls := []struct {
		name string
		args []string
		want []string // denial keys the one JSON object must carry; nil = no output
	}{
		{"preToolUse", []string{"--event", "preToolUse"}, []string{"permissionDecision"}},
		{"permissionRequest", []string{"--event", "permissionRequest"}, []string{"behavior"}},
		{"sessionStart", []string{"--event", "sessionStart"}, nil},
		{"unbound", nil, []string{"permissionDecision", "behavior"}},
		{"unreviewed event", []string{"--event", "toolUse"}, []string{"permissionDecision", "behavior"}},
	}
	for _, release := range []string{"0.8.10", "1.0.0", "1.0.3"} {
		for _, failure := range failures {
			for _, call := range calls {
				t.Run(release+"/"+failure.name+"/"+call.name, func(t *testing.T) {
					home := t.TempDir()
					hookDir := filepath.Join(home, ".defenseclaw", "hooks")
					if err := os.MkdirAll(hookDir, 0o700); err != nil {
						t.Fatal(err)
					}
					for _, name := range []string{"_hardening.sh", "copilot-hook.sh"} {
						body, err := os.ReadFile(filepath.Join("testdata", "released-hooks", release, name))
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(hookDir, name), body, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := RefreshHookFailModes(hookDir, func(string) string { return "closed" }); err != nil {
						t.Fatal(err)
					}
					dataDir := failure.setup(t, hookDir)
					out, code := runReleasedCopilotEarlyFailure(t, filepath.Join(hookDir, "copilot-hook.sh"), home, dataDir, call.args)
					if code != 0 {
						t.Fatalf("exit %d stdout=%q", code, out)
					}
					requireOneCopilotDenial(t, out, call.want)
				})
			}
		}
	}
}

func TestReleasedCopilotEarlyFailureRefusesAnUnknownDenial(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "released-hooks", "1.0.3", "copilot-hook.sh"))
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(body), `"DefenseClaw hook failed closed"}'`, `"DefenseClaw denied"}'`, 1)
	if edited == string(body) {
		t.Fatal("fixture has no early denial to edit")
	}
	if _, err := closeReleasedCopilotEarlyFailures(edited); err == nil {
		t.Fatal("an early denial the refresh does not know must be refused, not answered twice")
	}
}

// requireOneCopilotDenial fails unless out is exactly one JSON object whose
// deny keys are want (permissionDecision and/or behavior), or empty for nil.
func requireOneCopilotDenial(t *testing.T, out string, want []string) {
	t.Helper()
	if want == nil {
		if out != "" {
			t.Fatalf("stdout = %q, want no answer", out)
		}
		return
	}
	dec := json.NewDecoder(strings.NewReader(out))
	var answer map[string]any
	if err := dec.Decode(&answer); err != nil {
		t.Fatalf("stdout %q is not a JSON object: %v", out, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		t.Fatalf("stdout %q holds more than one JSON document (%v)", out, err)
	}
	for _, key := range []string{"permissionDecision", "behavior"} {
		_, has := answer[key]
		if has != slices.Contains(want, key) {
			t.Fatalf("stdout %q: %s present=%v, want keys %v", out, key, has, want)
		}
		if has && answer[key] != "deny" {
			t.Fatalf("stdout %q: %s = %v, want deny", out, key, answer[key])
		}
	}
}

func runReleasedCopilotEarlyFailure(t *testing.T, hook, home, dataDir string, args []string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{hook}, args...)...)
	cmd.Stdin = strings.NewReader(`{"sessionId":"s","toolName":"bash","toolArgs":{"command":"echo ok"}}`)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+dataDir)
	out, err := cmd.Output()
	return string(out), exitCodeOf(err)
}
