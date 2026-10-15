// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package hookexec runs DefenseClaw agent hooks natively in Go instead of via
// the bundled Bash hook scripts. It is the execution path used on Windows,
// where agents invoke the DefenseClaw binary directly (no Git Bash, no .cmd
// wrapper, no jq, and no PATH lockdown — because Go never shells out).
//
// The behavior here mirrors the .sh hooks under internal/gateway/connector/hooks:
// the same gateway endpoint, per-connector stdout shape and exit code, and the
// same fail-open-on-outage / fail-closed-on-misconfig policy. Native transport
// deadlines may follow the agent's registered event budget. Unix keeps using
// the .sh hooks unchanged; golden tests pin the shared decision contract.
package hookexec

import "testing"

// TestResolveHookWriteTargetsSurvivesResolverFailure pins that a payload the
// write-target resolver cannot handle does not crash the hook: the call is
// reported unresolved, so the gateway judges it fail-closed.
func TestResolveHookWriteTargetsSurvivesResolverFailure(t *testing.T) {
	for _, command := range []string{">x", ">x; cat ~/.ssh/id_rsa", ">>x; rm -rf /"} {
		payload := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":` + quote(command) + `}}`)
		resolved, ok := resolveHookWriteTargets(payload)
		if ok || resolved != "" {
			t.Fatalf("%q: got resolved=%q ok=%t, want the unresolved result", command, resolved, ok)
		}
	}
	if resolved, ok := resolveHookWriteTargets([]byte(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`)); !ok {
		t.Fatalf("plain command reported unresolved (%q)", resolved)
	}
}

func quote(s string) string {
	out := []byte{'"'}
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(append(out, '"'))
}
