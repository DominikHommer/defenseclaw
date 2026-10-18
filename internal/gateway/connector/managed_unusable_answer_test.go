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
	"os/exec"
	"strings"
	"testing"
)

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
