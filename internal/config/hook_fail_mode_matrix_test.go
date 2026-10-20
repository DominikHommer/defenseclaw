// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// The effective hook fail mode of every connector (owner rule 2026-10-14,
// restated 2026-10-20: open under Secure Client, closed everywhere else):
// per-user unset is closed (Cursor observe follows its guardrail mode),
// explicit open opens, managed standalone is always closed, and Secure Client
// resolves an unset value open for every connector, Codex and Claude Code
// included, in observe and action mode alike, while its explicit closed
// stays closed.
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
			check(cfg, "Secure Client observe unset", "open")
			cfg.Guardrail.Mode = "action"
			check(cfg, "Secure Client action unset", "open")
			cfg.Guardrail.HookFailMode = "closed"
			check(cfg, "Secure Client action global closed", "closed")
			cfg.Guardrail.Mode = "observe"
			check(cfg, "Secure Client observe global closed", "closed")
			cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{name: {HookFailMode: "open"}}
			check(cfg, "Secure Client connector open over global closed", "open")
			cfg.Guardrail.HookFailMode = ""
			cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{name: {HookFailMode: "closed"}}
			check(cfg, "Secure Client connector closed", "closed")
		})
	}
}
