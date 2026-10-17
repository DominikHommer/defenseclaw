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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lastHookFailure is the last line of the hook-failure log under home.
func lastHookFailure(t *testing.T, home string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
	if err != nil {
		t.Fatalf("read hook-failures.jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var entry map[string]string
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("decode %q: %v", lines[len(lines)-1], err)
	}
	return entry
}

func hermesBlockMessage(t *testing.T, stdout string) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(bytes.TrimSpace([]byte(stdout)), &body); err != nil || body["action"] != "block" {
		t.Fatalf("stdout = %q, want a Hermes block directive", stdout)
	}
	return body["message"]
}

// rel-1-0-2 GAP-0423: on a managed deployment outside Secure Client the
// native Hermes hook (Windows) blocks a tool call DefenseClaw cannot check,
// in every failure layer, says why, and logs the call as failed closed.
func TestManagedHermesToolCallBlocksWhenDefenseClawCannotCheck(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		rt         *stubRT
		mutate     func(*Options)
	}{
		{name: "gateway unreachable", want: "the DefenseClaw gateway is not available",
			rt: &stubRT{err: errors.New("connection refused")}},
		{name: "gateway 5xx", want: "the DefenseClaw gateway is not available",
			rt: &stubRT{status: 503, body: "unavailable"}},
		{name: "gateway refused", want: "returned an answer DefenseClaw could not use",
			rt: &stubRT{status: 401, body: "unauthorized"}},
		{name: "malformed answer", want: "returned an answer DefenseClaw could not use", rt: ok("not-json")},
		{name: "block without directive", want: "returned an answer DefenseClaw could not use",
			rt: ok(`{"action":"block","reason":"policy"}`)},
		{name: "oversized", want: "too large for DefenseClaw to inspect", rt: ok(`{"action":"allow"}`),
			mutate: func(o *Options) { o.MaxBody = 2 }},
		{name: "missing token", want: "the DefenseClaw gateway is not available", rt: ok(`{"action":"allow"}`),
			mutate: func(o *Options) {
				o.Token = ""
				o.HookDir = filepath.Join(o.Home, "no-token")
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var home string
			result := run(t, "hermes", tc.rt, func(o *Options) {
				o.Event = "pre_tool_call"
				o.FailMode = "open"
				o.ManagedEnterprise = true
				o.ExplainUnenrolledAccount = true
				o.Stdin = strings.NewReader(`{"hook_event_name":"pre_tool_call","tool_name":"terminal"}`)
				if tc.mutate != nil {
					tc.mutate(o)
				}
				home = o.Home
			})
			message := hermesBlockMessage(t, result.stdout)
			if result.code != 0 || !strings.HasPrefix(message, "DefenseClaw blocked this tool call: ") ||
				!strings.Contains(message, tc.want) {
				t.Fatalf("code %d, message %q, want a tool-call block naming %q (stderr %q)", result.code, message, tc.want, result.stderr)
			}
			if got := lastHookFailure(t, home)["fail_mode"]; got != "closed" {
				t.Fatalf("logged fail_mode = %q, want closed", got)
			}
		})
	}
}

// The Windows standalone hook resolves a stopped gateway service before it
// sends anything (ManagedRuntimeFailure); Hermes then says the service is
// not running, and an unenrolled account is told so.
func TestManagedHermesNativeRuntimeFailureNamesTheCause(t *testing.T) {
	for reason, want := range map[string]string{
		managedGatewayNotRunningReason: "the DefenseClaw gateway service is not running on this computer",
		managedSIDUnregisteredReason:   "this account is not enrolled yet",
	} {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), Options{
			Connector:                "hermes",
			Event:                    "pre_tool_call",
			ManagedEnterprise:        true,
			ExplainUnenrolledAccount: true,
			ManagedRuntimeFailure:    reason,
			Home:                     t.TempDir(),
			Stdin:                    strings.NewReader(`{"hook_event_name":"pre_tool_call"}`),
			Stdout:                   &stdout,
			Stderr:                   &stderr,
		})
		if message := hermesBlockMessage(t, stdout.String()); code != 0 || !strings.Contains(message, want) {
			t.Fatalf("%s: code %d, message %q, want %q", reason, code, message, want)
		}
	}
}

// Per-user and Secure Client Hermes hooks, and Hermes events that cannot
// block, keep the neutral result; the log says the call ran fail-open
// (rel-1-0-2 GAP-0446 item 5: a closed configured mode was logged before).
func TestHermesNeutralResultOutsideManagedToolCalls(t *testing.T) {
	for name, mutate := range map[string]func(*Options){
		"per-user": func(o *Options) {},
		"secure client": func(o *Options) {
			o.ManagedEnterprise = true
			o.SecureClient = true
		},
		"managed pre_llm_call": func(o *Options) {
			o.ManagedEnterprise = true
			o.ExplainUnenrolledAccount = true
			o.Event = "pre_llm_call"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var home string
			result := run(t, "hermes", &stubRT{err: errors.New("connection refused")}, func(o *Options) {
				o.Event = "pre_tool_call"
				o.FailMode = "closed"
				o.StrictAvailability = true
				mutate(o)
				home = o.Home
			})
			if result.code != 0 || strings.Contains(result.stdout, `"block"`) {
				t.Fatalf("code %d, stdout %q, want the neutral result", result.code, result.stdout)
			}
			if got := lastHookFailure(t, home)["fail_mode"]; got != "open" {
				t.Fatalf("logged fail_mode = %q, want open", got)
			}
		})
	}
}
