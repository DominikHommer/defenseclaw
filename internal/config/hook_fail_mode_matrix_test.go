// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// The effective hook fail mode of every connector (B-01 merge review matrix):
// per-user unset is closed (Cursor observe follows its guardrail mode),
// explicit open opens, managed standalone is always closed, and Secure
// Client keeps an unset observe connector open except the pinned native
// Claude Code and Codex hooks; Secure Client action is closed.
func TestEveryConnectorHookFailModeMatrix(t *testing.T) {
	names := []string{"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "opencode", "openhands"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			check := func(cfg *Config, what, want string) {
				t.Helper()
				if got := cfg.EffectiveHookFailModeForConnector(name); got != want {
					t.Fatalf("%s = %q, want %q", what, got, want)
				}
			}
			cfg := &Config{}
			cfg.Guardrail.Mode = "observe"
			want := "closed"
			if name == "cursor" {
				want = "open"
			}
			check(cfg, "per-user observe unset", want)
			cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{name: {HookFailMode: "open"}}
			check(cfg, "per-user observe explicit open", "open")
			cfg.Guardrail.Mode = "action"
			want = "open"
			if name == "cursor" {
				want = "closed"
			}
			check(cfg, "per-user action explicit open", want)
			cfg.Guardrail.Connectors = nil
			check(cfg, "per-user action unset", "closed")
			cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{name: {HookFailMode: "open"}}
			cfg.DeploymentMode = "managed_enterprise"
			cfg.Enterprise.Profile = "standalone"
			check(cfg, "standalone action explicit open", "closed")
			cfg.Guardrail.Mode = "observe"
			check(cfg, "standalone observe explicit open", "closed")
			cfg.Guardrail.Connectors = nil
			check(cfg, "standalone observe unset", "closed")
			cfg.Enterprise.Profile = "secure_client"
			want = "open"
			if name == "codex" || name == "claudecode" {
				want = "closed"
			}
			check(cfg, "Secure Client observe unset", want)
			cfg.Guardrail.Mode = "action"
			check(cfg, "Secure Client action unset", "closed")
		})
	}
}
