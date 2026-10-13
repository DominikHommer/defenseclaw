// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCodexStopWithoutVerdictUsesNeutralResult(t *testing.T) {
	causes := []struct {
		name        string
		rt          func() *stubRT
		mutate      func(*Options)
		perUserOnly bool
		managedOnly bool
	}{
		{name: "transport", rt: func() *stubRT { return &stubRT{err: errors.New("gateway unavailable")} }},
		{name: "HTTP response", rt: func() *stubRT { return &stubRT{status: 401, body: "{"} }},
		{name: "unparseable response", rt: func() *stubRT { return ok(`{`) }},
		{name: "unusable response", rt: func() *stubRT { return ok(`{"action":"unknown"}`) }},
		{name: "oversized body", rt: func() *stubRT { return ok(`{"action":"allow"}`) }, mutate: func(o *Options) { o.MaxBody = 1 }},
		{name: "unavailable home", rt: func() *stubRT { return ok(`{"action":"allow"}`) }, mutate: func(o *Options) {
			o.Home = filepath.Join(o.Home, "missing")
		}},
		{name: "missing credential", rt: func() *stubRT { return ok(`{"action":"allow"}`) }, perUserOnly: true, mutate: func(o *Options) {
			o.HookDir = filepath.Join(o.HookDir, "missing")
		}},
		{name: "request budget", rt: func() *stubRT { return ok(`{"action":"allow"}`) }, mutate: func(o *Options) {
			o.StartedAt = time.Now().Add(-time.Minute)
		}},
		{name: "runtime unavailable", rt: func() *stubRT { return ok(`{"action":"allow"}`) }, managedOnly: true, mutate: func(o *Options) {
			o.ManagedRuntimeFailure = "enterprise_managed_runtime_invalid"
		}},
		{name: "hook socket missing", rt: func() *stubRT { return ok(`{"action":"allow"}`) }, managedOnly: true, mutate: func(o *Options) {
			o.ManagedUnixSocket = ""
		}},
	}
	for _, profile := range []struct {
		name    string
		managed bool
	}{
		{name: "per-user"},
		{name: "managed standalone", managed: true},
	} {
		for _, cause := range causes {
			if (cause.perUserOnly && profile.managed) || (cause.managedOnly && !profile.managed) {
				continue
			}
			for _, event := range []string{"Stop", "PreToolUse", "PermissionRequest", "UserPromptSubmit"} {
				t.Run(profile.name+"/"+cause.name+"/"+event, func(t *testing.T) {
					var home string
					r := run(t, "codex", cause.rt(), func(o *Options) {
						o.Event = event
						o.FailMode = "closed"
						o.StrictAvailability = true
						o.ManagedEnterprise = profile.managed
						o.ManagedStandalone = profile.managed
						o.ManagedUnixSocket = "/run/defenseclaw-hook/hook.sock"
						if cause.mutate != nil {
							cause.mutate(o)
						}
						home = o.Home
					})
					if event == "Stop" {
						if r.code != 0 || r.stdout != "" || !strings.Contains(r.stderr, "not blocking the Stop event") {
							t.Fatalf("failed Stop = code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
						}
					} else if r.code == 0 && !strings.Contains(r.stdout, `"block"`) && !strings.Contains(r.stdout, `"deny"`) {
						t.Fatalf("failed %s did not block: code %d, stdout %q, stderr %q", event, r.code, r.stdout, r.stderr)
					}
					if event == "Stop" {
						data, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
						if err != nil || !strings.Contains(string(data), `"fail_mode":"closed"`) {
							t.Fatalf("failure log = %q, %v", data, err)
						}
					}
				})
			}
		}
	}
	for _, managed := range []bool{false, true} {
		r := run(t, "codex", ok(`{"action":"block","reason":"Policy block","codex_output":{"decision":"block","reason":"Policy block"}}`), func(o *Options) {
			o.Event = "Stop"
			o.FailMode = "closed"
			o.ManagedEnterprise = managed
			o.ManagedStandalone = managed
			o.ManagedUnixSocket = "/run/defenseclaw-hook/hook.sock"
		})
		if r.code != 0 || !strings.Contains(r.stdout, `"decision":"block"`) {
			t.Fatalf("managed=%v: code %d, stdout %q, stderr %q", managed, r.code, r.stdout, r.stderr)
		}
	}
}
