// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// TestEveryConnectorFailsClosedUnlessPerUserExplicitOpen is the main-sync
// regression (rel-1-0-3 MAINSYNC, review rulings 1 and 4): for every
// connector, per-user and managed standalone, in observe and action mode,
// with the fail mode unset, empty, explicit open (global or per connector)
// or explicit closed, the effective hook fail mode is closed. The only
// exceptions are an explicit per-user open and the per-user Cursor rule
// (observe open, action closed, whatever is configured); the Secure Client
// rows are pinned by TestEveryConnectorHookFailModeMatrix.
func TestEveryConnectorFailsClosedUnlessPerUserExplicitOpen(t *testing.T) {
	names := []string{"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "opencode", "openhands"}
	type setting struct {
		name           string
		global, perCon string
		explicitOpen   bool
	}
	settings := []setting{
		{name: "unset"},
		{name: "empty", global: " ", perCon: ""},
		{name: "global open", global: "open", explicitOpen: true},
		{name: "global Open", global: " Open ", explicitOpen: true},
		{name: "connector open", perCon: "open", explicitOpen: true},
		{name: "global closed", global: "closed"},
		{name: "connector closed over global open", global: "open", perCon: "closed"},
		{name: "global typo", global: "opne"},
	}
	deployments := []struct{ name, mode, profile string }{
		{"per-user", "", ""},
		{"unmanaged", "unmanaged_byod", ""},
		{"standalone", "managed_enterprise", "standalone"},
	}
	for _, name := range names {
		for _, d := range deployments {
			for _, mode := range []string{"observe", "action"} {
				for _, s := range settings {
					cfg := &Config{DeploymentMode: d.mode}
					cfg.Enterprise.Profile = d.profile
					cfg.Guardrail.Mode = mode
					cfg.Guardrail.HookFailMode = s.global
					if s.perCon != "" {
						cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{name: {HookFailMode: s.perCon}}
					}
					want := "closed"
					if d.profile != "standalone" {
						switch {
						case name == "cursor" && mode == "observe":
							want = "open"
						case name == "cursor":
							want = "closed"
						case s.explicitOpen:
							want = "open"
						}
					}
					if got := cfg.EffectiveHookFailModeForConnector(name); got != want {
						t.Errorf("%s %s %s %s: fail mode = %q, want %q", name, d.name, mode, s.name, got, want)
					}
					if d.profile == "standalone" {
						if got := cfg.EffectiveActionHookFailModeForConnector(name); got != "closed" {
							t.Errorf("%s standalone %s %s: action fail mode = %q, want closed", name, mode, s.name, got)
						}
					}
				}
			}
		}
	}
}
