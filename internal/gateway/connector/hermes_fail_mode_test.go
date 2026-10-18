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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0150: a per-user Hermes hook with an unset hook_fail_mode resolves
// closed outside Secure Client; only an explicit "open" renders open.
func TestPerUserHermesHookKeepsTheResolvedFailMode(t *testing.T) {
	for _, tc := range []struct {
		name, mode, want string
	}{
		{name: "unset", mode: "", want: "closed"},
		{name: "closed", mode: "closed", want: "closed"},
		{name: "open", mode: "open", want: "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			opts := SetupOpts{
				DataDir:       filepath.Join(dir, "dc"),
				APIAddr:       "127.0.0.1:18970",
				APIToken:      "tok-test",
				HookFailMode:  tc.mode,
				GuardrailMode: "action",
				WorkspaceDir:  dir,
			}
			hookDir := filepath.Join(dir, "hooks")
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewHermesConnector()); err != nil {
				t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
			}
			body, err := os.ReadFile(filepath.Join(hookDir, "hermes-hook.sh"))
			if err != nil {
				t.Fatalf("read hermes-hook.sh: %v", err)
			}
			if want := `FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-` + tc.want + `}"`; !strings.Contains(string(body), want) {
				t.Fatalf("hermes-hook.sh does not render %s", want)
			}
			flat, err := os.ReadFile(filepath.Join(hookDir, hookConfigSidecarName+".hermes"))
			if err != nil {
				t.Fatalf("read the Hermes runtime record: %v", err)
			}
			if want := "DEFENSECLAW_FAIL_MODE=" + tc.want + "\n"; !strings.Contains(string(flat), want) {
				t.Fatalf("runtime record = %q, want %q", flat, want)
			}
			if got := HookFailClosed(opts, NewHermesConnector()); got != (tc.want == "closed") {
				t.Fatalf("HookFailClosed = %v, want %v", got, tc.want == "closed")
			}
		})
	}
}

// GAP-0150: with the gateway down, the per-user Hermes hook rendered with an
// unset fail mode prints Hermes' block directive with the next step, so the
// tool call does not run.
func TestPerUserHermesHookBlocksAToolCallWhileTheGatewayIsDown(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	dir := t.TempDir()
	hookDir := filepath.Join(dir, "hooks")
	opts := SetupOpts{
		DataDir:       filepath.Join(dir, "dc"),
		APIAddr:       freeAPIAddr(t),
		APIToken:      "tok-test",
		GuardrailMode: "action",
		WorkspaceDir:  dir,
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewHermesConnector()); err != nil {
		t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
	}
	home := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(hookDir, "hermes-hook.sh"))
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo ok"}}`)
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "DEFENSECLAW_") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(env, "DEFENSECLAW_HOME="+home, "HOME="+home)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	out := stdout.String()
	if !strings.Contains(out, `"action":"block"`) || !strings.Contains(out, "defenseclaw-gateway status") {
		t.Fatalf("stdout = %q (stderr %q), want a Hermes block directive that names defenseclaw-gateway status", out, stderr.String())
	}
}
