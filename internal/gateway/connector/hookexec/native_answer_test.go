// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// A per-user Copilot CLI hook bound to no reviewed event cannot tell
// preToolUse from permissionRequest: in fail mode closed (or strict
// availability) it writes both of Copilot's denies and says how to register
// the hook again, like the standalone hook; in fail mode open the call runs.
// The gateway is never asked.
func TestPerUserCopilotHookRefusesAnUnboundEvent(t *testing.T) {
	for _, event := range []string{"", "futureEvent", "PreToolUse"} {
		for _, mode := range []string{"closed", "strict", "open"} {
			t.Run(event+"/"+mode, func(t *testing.T) {
				rt := ok(`{"action":"allow"}`)
				result := run(t, "copilot", rt, func(opts *Options) {
					opts.Event = event
					opts.FailMode = "closed"
					switch mode {
					case "strict":
						opts.FailMode = "open"
						opts.StrictAvailability = true
					case "open":
						opts.FailMode = "open"
					}
				})
				if rt.requests != 0 {
					t.Fatalf("unbound event %q reached the gateway", event)
				}
				if mode == "open" {
					if result.code != 0 || result.stdout != "" {
						t.Fatalf("open: code=%d stdout=%q, want the fail-open result", result.code, result.stdout)
					}
					return
				}
				if result.code != 0 || !strings.Contains(result.stdout, `"permissionDecision":"deny"`) ||
					!strings.Contains(result.stdout, `"behavior":"deny"`) || !strings.Contains(result.stdout, "defenseclaw setup copilot") ||
					strings.Contains(result.stdout, "administrator") {
					t.Fatalf("code=%d stdout=%q stderr=%q, want both denies with the per-user next step",
						result.code, result.stdout, result.stderr)
				}
			})
		}
	}
}

// A closed per-user Copilot CLI or Antigravity hook accepts a confirmation
// only with the agent's native ask and a block only with its native deny, as
// copilot-hook.sh and antigravity-hook.sh check; anything else is no verdict
// and is denied. A real ask passes through, and fail mode open lets an
// unusable answer run.
func TestPerUserHookDeniesAnAnswerWithoutTheNativeDecision(t *testing.T) {
	for _, tc := range []struct {
		name, connector, event, body, mode, want string
	}{
		{"copilot preToolUse confirm", "copilot", "preToolUse", `{"action":"confirm"}`, "closed", `"permissionDecision":"deny"`},
		{"copilot preToolUse confirm allow", "copilot", "preToolUse",
			`{"action":"confirm","hook_output":{"permissionDecision":"allow"}}`, "closed", `"permissionDecision":"deny"`},
		{"copilot permissionRequest confirm", "copilot", "permissionRequest", `{"action":"confirm"}`, "closed", `"behavior":"deny"`},
		{"copilot preToolUse ask", "copilot", "preToolUse",
			`{"action":"confirm","hook_output":{"permissionDecision":"ask","permissionDecisionReason":"check"}}`, "closed", `"permissionDecision":"ask"`},
		{"antigravity confirm", "antigravity", "PreToolUse", `{"action":"confirm"}`, "closed", `"decision":"deny"`},
		{"antigravity confirm allow", "antigravity", "PreToolUse",
			`{"action":"confirm","hook_output":{"decision":"allow"}}`, "closed", `"decision":"deny"`},
		{"antigravity block", "antigravity", "PreToolUse", `{"action":"block"}`, "closed", `"decision":"deny"`},
		{"antigravity ask", "antigravity", "PreToolUse",
			`{"action":"confirm","hook_output":{"decision":"ask","reason":"check"}}`, "closed", `"decision":"ask"`},
		{"antigravity confirm open", "antigravity", "PreToolUse", `{"action":"confirm"}`, "open", `"decision":"allow"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, tc.connector, ok(tc.body), func(opts *Options) {
				opts.Event = tc.event
				opts.FailMode = tc.mode
			})
			if result.code != 0 || !strings.Contains(result.stdout, tc.want) || strings.Count(result.stdout, "\n") != 1 {
				t.Fatalf("code=%d stdout=%q stderr=%q, want one answer with %s", result.code, result.stdout, result.stderr, tc.want)
			}
		})
	}
}
