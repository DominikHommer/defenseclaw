// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rel-1-0-3 GAP-0037: a managed standalone render keeps the closed fail mode
// the managed config resolved, for Cursor in observe mode and for the
// connectors without a fail-closed hook contract of their own. Secure Client
// and per-user renders keep their rules.
func TestManagedStandaloneRenderKeepsClosed(t *testing.T) {
	standalone := SetupOpts{ManagedEnterprise: true, ManagedHookSocket: "/run/defenseclaw/hook.sock", HookFailMode: "closed", GuardrailMode: "observe"}
	secureClient := SetupOpts{ManagedEnterprise: true, HookFailMode: "closed", GuardrailMode: "observe"}
	perUser := SetupOpts{HookFailMode: "closed", GuardrailMode: "observe"}
	for _, test := range []struct {
		name string
		conn Connector
		opts SetupOpts
		want string
	}{
		{"standalone cursor observe", NewCursorConnector(), standalone, "closed"},
		{"standalone hermes", NewHermesConnector(), standalone, "closed"},
		{"standalone copilot", NewCopilotConnector(), standalone, "closed"},
		{"secure client hermes", NewHermesConnector(), secureClient, "open"},
		{"secure client cursor observe", NewCursorConnector(), secureClient, "open"},
		{"per-user cursor observe", NewCursorConnector(), perUser, "open"},
		{"per-user hermes", NewHermesConnector(), perUser, "open"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := CapableHookFailMode(test.opts, test.conn, resolveHookFailMode(test.opts, test.conn)); got != test.want {
				t.Fatalf("rendered fail mode = %q, want %q", got, test.want)
			}
		})
	}
}

// A managed shell hook takes only its rendered fail mode: a fail mode in the
// environment cannot reopen it. Per-user hooks keep the override.
func TestManagedShellHooksIgnoreTheEnvironmentFailMode(t *testing.T) {
	for _, name := range []string{
		"antigravity-hook.sh", "claude-code-hook.sh", "codex-hook.sh", "cursor-hook.sh",
		"devin-hook.sh", "hermes-hook.sh", "kiro-hook.sh", "openhands-hook.sh",
	} {
		for _, managed := range []bool{true, false} {
			scripts, err := renderHookScripts("127.0.0.1:18970", "closed", ".token", []string{name}, managed, strings.TrimSuffix(name, "-hook.sh"), true, "", "", false)
			if err != nil {
				t.Fatalf("render %s: %v", name, err)
			}
			for _, script := range scripts {
				if script.name != name {
					continue
				}
				body := string(script.body)
				// The baked line keeps its form for doctor and status; a
				// managed hook pins the rendered value right after it.
				if !strings.Contains(body, `FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-closed}"`) {
					t.Errorf("%s managed=%v: baked fail-mode line missing", name, managed)
				}
				pinned := strings.Contains(body, "FAIL_MODE=\"${DEFENSECLAW_FAIL_MODE:-closed}\"\nFAIL_MODE=\"closed\"\n")
				if managed != pinned {
					t.Errorf("%s managed=%v: rendered fail mode pinned = %v", name, managed, pinned)
				}
			}
		}
	}
}

// rel-1-0-2 GAP-0530: a standalone Hermes hook that cannot get a verdict
// blocks the tool call with a message that says why, and a fail mode in the
// environment does not turn a response failure into an allow.
func TestManagedStandaloneHermesHookBlockSaysWhy(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		if _, err := os.Stat("/usr/local/bin/jq"); err != nil {
			t.Skip("jq is required to run the Hermes shell hook")
		}
	}
	f := newHookSocketFixture(t, "dchm", "an answer without a verdict")
	code, stdout, stderr := runStandaloneHermesHook(t, f)
	if code != 0 || !strings.Contains(stdout, `"action":"block"`) ||
		!strings.Contains(stdout, "DefenseClaw blocked this tool call: the DefenseClaw gateway returned an answer DefenseClaw could not use") {
		t.Fatalf("unusable answer: exit %d stdout=%q stderr=%q, want a block that says why", code, stdout, stderr)
	}
	if err := os.Remove(f.socket); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runStandaloneHermesHook(t, f)
	if code != 2 || !strings.Contains(stdout, `"action":"block"`) ||
		!strings.Contains(stdout, "DefenseClaw blocked this tool call: the DefenseClaw gateway service is not running on this computer") {
		t.Fatalf("stopped gateway: exit %d stdout=%q stderr=%q, want a block naming the stopped service", code, stdout, stderr)
	}
}

// rel-1-0-3 B-20 review item 1: a managed standalone shell hook blocks a
// successful gateway answer that carries no usable verdict (no action, an
// unknown one, a block without a directive or with one that does not deny),
// with DEFENSECLAW_FAIL_MODE=open in the environment. The allow and alert
// answers of observe mode still let the call run.
func TestManagedStandaloneShellHooksBlockAnUnusableAnswer(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required to run the shell hooks")
	}
	for _, conn := range []Connector{
		NewHermesConnector(), NewKiroConnector(), NewCursorConnector(),
		NewDevinConnector(), NewAntigravityConnector(), NewOpenHandsConnector(),
	} {
		hook := hookArgvConnectorCase(t, conn.Name())
		for _, answer := range []struct {
			name   string
			body   map[string]any
			blocks bool
		}{
			{"missing action", map[string]any{}, true},
			{"unknown action", map[string]any{"action": "proceed"}, true},
			{"block without directive", map[string]any{"action": "block"}, true},
			{"block whose directive allows", map[string]any{"action": "block", "hook_output": map[string]string{"decision": "allow"}}, true},
			{"observe allow", map[string]any{"action": "allow"}, false},
			{"observe alert", map[string]any{"action": "alert"}, false},
		} {
			t.Run(conn.Name()+" "+answer.name, func(t *testing.T) {
				f := newHookSocketFixture(t, "dcua", answer.body)
				code, stdout, stderr := runStandaloneShellHook(t, f, conn, hook.script, hook.args, hook.stdin)
				blocked := code == 2 || strings.Contains(stdout, `"deny"`) ||
					strings.Contains(stdout, `"block"`) || strings.Contains(stdout, `"continue":false`)
				if blocked != answer.blocks {
					t.Fatalf("exit %d stdout=%q stderr=%q: blocked = %v, want %v", code, stdout, stderr, blocked, answer.blocks)
				}
			})
		}
	}
}

// runStandaloneHermesHook runs the standalone Hermes hook (runStandaloneShellHook)
// for one tool call.
func runStandaloneHermesHook(t *testing.T, f *hookSocketFixture) (int, string, string) {
	t.Helper()
	return runStandaloneShellHook(t, f, NewHermesConnector(), "hermes-hook.sh", nil,
		`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo marker"}}`)
}

// runStandaloneShellHook renders conn's hooks for a standalone install in
// observe mode on f's socket and runs script once with args and stdin, with
// DEFENSECLAW_FAIL_MODE=open in the environment.
func runStandaloneShellHook(t *testing.T, f *hookSocketFixture, conn Connector, script string, args []string, stdin string) (int, string, string) {
	t.Helper()
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is required to run shell hooks")
	}
	dataDir := filepath.Join(f.root, "home", ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	opts := SetupOpts{
		DataDir:            dataDir,
		APIAddr:            f.held.Addr().String(),
		HookAPIToken:       "connector-scoped-token",
		HookAPITokenScoped: true,
		ManagedEnterprise:  true,
		HookFailMode:       "closed",
		GuardrailMode:      "observe",
		ManagedHookSocket:  f.socket,
		ManagedServiceUID:  os.Getuid(),
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hookDir, script)
	bakeHookPathForTest(t, hookPath, filepath.Dir(curlPath)+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", append([]string{hookPath}, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+filepath.Join(f.root, "home"), "DEFENSECLAW_FAIL_MODE=open")
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run hook: %v", err)
	}
	return code, stdout.String(), stderr.String()
}
