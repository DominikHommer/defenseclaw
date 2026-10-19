// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestFixedHookSchemasAreClosedAndCommandsStayJSON(t *testing.T) {
	seen := map[string]bool{}
	for _, value := range Cases() {
		if seen[value.Name] || value.Name == "" {
			t.Fatal("duplicate/empty fixed schema")
		}
		seen[value.Name] = true
		for _, phase := range []byte{'A', 'B', 'L'} {
			raw, err := value.Payload(phase)
			if err != nil || !json.Valid(raw) || bytes.Contains(raw, []byte("COMMAND")) {
				t.Fatal("invalid fixed schema", value.Name)
			}
		}
		if _, err := value.Payload('X'); err == nil {
			t.Fatal("unknown command admitted")
		}
	}
	if len(seen) != 12 {
		t.Fatal("fixed inventory changed")
	}
	if _, err := Lookup("unknown"); err == nil {
		t.Fatal("unknown connector admitted")
	}
	claude, _ := Lookup("claudecode")
	if claude.NativeSurface != "structured-deny-exit0; admission-loss-exit2" {
		t.Fatal("fixed Claude surface differs")
	}
	checkClaudeResponseFixtures(t)
}

func checkClaudeResponseFixtures(t *testing.T) {
	t.Helper()
	deny := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"fixed policy reason"}}` + "\n"
	closed := "defenseclaw: gateway unreachable, blocking claude-code tool (fail mode closed): gateway returned HTTP 503\n"
	for _, row := range []Row{{Phase: "A"}, {Phase: "B", Stdout: deny}, {Phase: "L", Code: 2, Stderr: closed}} {
		if ValidateClaudeRow(row.Phase[0], row) != nil {
			t.Fatal("existing fixed Claude response refused")
		}
	}
	// An exit-0 allow, fallback exit-2 block, wrong event, or ambiguous JSON
	// cannot masquerade as the structured denial the actual evaluator emits.
	for _, row := range []Row{
		{Phase: "B"},
		{Phase: "B", Code: 2, Stdout: deny},
		{Phase: "B", Stdout: strings.Replace(deny, `"deny"`, `"allow"`, 1)},
		{Phase: "B", Stdout: strings.Replace(deny, `"PreToolUse"`, `"PostToolUse"`, 1)},
		{Phase: "B", Stdout: strings.Replace(deny, `"fixed policy reason"`, `" "`, 1)},
		{Phase: "B", Stdout: strings.Replace(deny, `"fixed policy reason"`, `null`, 1)},
		{Phase: "B", Stdout: strings.Replace(deny, `"permissionDecision":"deny"`, `"permissionDecision":"allow","permissionDecision":"deny"`, 1)},
		{Phase: "B", Stdout: strings.TrimSpace(deny[:len(deny)-2]) + `,"hookSpecificOutput":{}}`},
		{Phase: "B", Stdout: strings.Replace(deny, `"hookEventName"`, `"extra":true,"hookEventName"`, 1)},
		{Phase: "B", Stdout: strings.Replace(deny, `{"hookSpecificOutput"`, `{"continue":true,"hookSpecificOutput"`, 1)},
		{Phase: "B", Stdout: deny + `{}`},
		{Phase: "B", Stdout: `null`},
		{Phase: "B", Stdout: `{"hookSpecificOutput":`},
		{Phase: "B", Stdout: deny, Stderr: "unexpected"},
		{Phase: "B", Stdout: strings.Repeat(" ", 16385)},
		{Phase: "A", Code: 2},
		{Phase: "A", Stdout: deny},
		{Phase: "A", Stderr: "unexpected"},
		{Phase: "L", Stderr: closed},
		{Phase: "L", Code: 2, Stderr: closed, Stdout: deny},
		{Phase: "L", Code: 2, Stderr: strings.Replace(closed, "503", "502", 1)},
		{Phase: "L", Code: 2, Stderr: strings.TrimSpace(closed)},
		{Phase: "L", Code: 2},
		{Phase: "X"},
	} {
		if ValidateClaudeRow(row.Phase[0], row) == nil {
			t.Fatal("malformed/allow/failure-shaped Claude response admitted")
		}
	}
	if ValidateClaudeRow('B', Row{Phase: "A", Stdout: deny}) == nil {
		t.Fatal("uncorrelated Claude phase admitted")
	}
}
