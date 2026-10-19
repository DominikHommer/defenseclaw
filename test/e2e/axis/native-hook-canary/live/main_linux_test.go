// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/test/e2e/axis/native-hook-canary/fixture"
)

const closedClaude503 = "defenseclaw: gateway unreachable, blocking claude-code tool (fail mode closed): gateway returned HTTP 503\n"
const deniedClaude = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"fixed deny"}}`

func validClaudeCase() map[string]any {
	value, _ := fixture.Lookup("claudecode")
	row := func(phase string, code int, stdout, stderr string) map[string]any {
		return map[string]any{"phase": phase, "hook_code": code, "hook_stdout": stdout, "hook_stderr": stderr}
	}
	decision := func(action string) map[string]any {
		return map[string]any{"BindingID": "fixed-binding", "SandboxName": "fixed-contained-hook-claudecode",
			"Connector": "claudecode", "Action": action, "WouldBlock": false}
	}
	return map[string]any{
		"scope": "fixed synthetic contained hook exchange", "connector": "claudecode",
		"declared_schema_version": value.Version, "native_surface": value.NativeSurface,
		"actual_synthetic_payload": "sha256:" + payloadSHA, "prepared": true, "started": true,
		"exited": true, "destroyed": true, "native_and_endpoint_cleanup": true,
		"binding_mint_attempted": true, "binding_issued": true, "binding_revoked": true,
		"vendor_runtime_qualification": false, "production_qualification": false,
		"binding_id": "fixed-binding", "audit_allow_and_block_durable": true,
		"rows": []any{row("A", 0, "", ""), row("B", 0, deniedClaude, ""),
			row("S", 0, "", ""), row("L", 2, "", closedClaude503)},
		"decisions": []any{decision("allow"), decision("block")},
	}
}

func TestStrictCaseJSONRefusesDuplicateKeys(t *testing.T) {
	for _, raw := range []string{
		`{"prepared":false,"prepared":true}`,
		`{"rows":[{"phase":"A","phase":"B"}]}`,
		`{"decisions":[{"Action":"allow","Action":"block"}]}`,
		`{"outer":{"inner":{"x":1,"x":2}}}`,
		`{"prepared":true}{"prepared":true}`,
	} {
		if _, err := strictObject([]byte(raw)); err == nil {
			t.Fatalf("duplicate or trailing JSON accepted: %s", raw)
		}
	}
	if _, err := strictObject([]byte(`{"rows":[{"phase":"A"}]}`)); err != nil {
		t.Fatal("ordinary fixed JSON refused:", err)
	}
}

func TestClaudeCaseRefusesFalsePass(t *testing.T) {
	if err := verifyCase(validClaudeCase(), "claudecode"); err != nil {
		t.Fatal("valid strict fixture refused:", err)
	}
	changes := map[string]func(map[string]any){
		"audit-durable-missing": func(item map[string]any) {
			delete(item, "audit_allow_and_block_durable")
		},
		"audit-durable-false": func(item map[string]any) {
			item["audit_allow_and_block_durable"] = false
		},
		"audit-durable-wrong-type": func(item map[string]any) {
			item["audit_allow_and_block_durable"] = "true"
		},
		"policy-denial-code-two": func(item map[string]any) {
			item["rows"].([]any)[1].(map[string]any)["hook_code"] = 2
		},
		"policy-denial-says-allow": func(item map[string]any) {
			item["rows"].([]any)[1].(map[string]any)["hook_stdout"] =
				`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"fixed"}}`
		},
		"policy-denial-duplicate-key": func(item map[string]any) {
			item["rows"].([]any)[1].(map[string]any)["hook_stdout"] =
				`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecision":"deny","permissionDecisionReason":"fixed"}}`
		},
		"silence-code": func(item map[string]any) {
			item["rows"].([]any)[2].(map[string]any)["hook_code"] = 2
		},
		"silence-output": func(item map[string]any) {
			item["rows"].([]any)[2].(map[string]any)["hook_stdout"] = "unexpected"
		},
		"closed-admission-code": func(item map[string]any) {
			item["rows"].([]any)[3].(map[string]any)["hook_code"] = 0
		},
		"closed-admission-stderr": func(item map[string]any) {
			item["rows"].([]any)[3].(map[string]any)["hook_stderr"] = "HTTP 503"
		},
		"wrong-schema": func(item map[string]any) {
			item["declared_schema_version"] = "other"
		},
		"wrong-binding-name": func(item map[string]any) {
			item["decisions"].([]any)[0].(map[string]any)["SandboxName"] = "other"
		},
		"wrong-decision": func(item map[string]any) {
			item["decisions"].([]any)[1].(map[string]any)["Action"] = "allow"
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			item := validClaudeCase()
			change(item)
			if err := verifyCase(item, "claudecode"); err == nil {
				t.Fatal("false-pass case accepted")
			}
		})
	}
}

func claudeTestOutput(record string) []byte {
	return []byte("=== RUN   " + claudeTest + "\n" +
		"    canary_test.go:1: CONTAINED_HOOK_RESULT " + record + "\n" +
		"    canary_test.go:2: CONTAINED_HOOK_CLEANUP_RESULT connector=claudecode resources_released=true incomplete=false\n" +
		"--- PASS: " + claudeTest + " (0.01s)\nPASS\n")
}

func TestOutputGateRejectsLastWinsRecord(t *testing.T) {
	raw, err := json.Marshal(validClaudeCase())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectResult(claudeTestOutput(string(raw)), "claude"); err != nil {
		t.Fatal("valid fixed output refused:", err)
	}
	duplicate := strings.Replace(string(raw), `"prepared":true`, `"prepared":false,"prepared":true`, 1)
	if duplicate == string(raw) {
		t.Fatal("negative mutation did not change fixed record")
	}
	if _, err := inspectResult(claudeTestOutput(duplicate), "claude"); err == nil {
		t.Fatal("last-wins case record accepted")
	}
	if _, err := inspectResult(claudeTestOutput(string(raw))[:len(claudeTestOutput(string(raw)))-5], "claude"); err == nil {
		t.Fatal("missing package PASS accepted")
	}
}
