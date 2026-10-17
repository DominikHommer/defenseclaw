// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedFailOpenConfig is an observe-mode config that asks for fail-open
// hooks everywhere it can: globally, per connector, through the automatic
// protection overlay and on an ACP profile.
func managedFailOpenConfig(deploymentMode, profile string) *Config {
	cfg := &Config{DeploymentMode: deploymentMode}
	cfg.Enterprise.Profile = profile
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.HookFailMode = "open"
	cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{
		"amp":  {Mode: "observe", HookFailMode: "open"},
		"kiro": {Mode: "observe", HookFailMode: "open"},
	}
	cfg.ApplicationProtection.Connectors = map[string]ApplicationProtectionConnectorConfig{
		"hermes": {Guardrail: PerConnectorGuardrailConfig{HookFailMode: "open"}},
	}
	cfg.ACP.Profiles = map[string]ACPProfile{
		"watch":  {Mode: "observe", FailMode: "open"},
		"locked": {Mode: "action", FailMode: "closed"},
	}
	return cfg
}

var managedFailModeConnectors = []string{
	"amp", "antigravity", "claudecode", "codex", "copilot", "cursor",
	"devin", "hermes", "kiro", "opencode", "openhands",
}

// rel-1-0-3 GAP-0037: outside Secure Client a managed deployment fails
// closed for every connector and guardrail mode, whatever hook_fail_mode
// says, so the hooks and status agree (owner rule 2026-10-14).
func TestManagedStandaloneHooksFailClosedForEveryConnector(t *testing.T) {
	cfg := managedFailOpenConfig(managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone)
	if !cfg.ManagedHooksFailClosed() {
		t.Fatal("ManagedHooksFailClosed() = false on the standalone profile")
	}
	for _, name := range managedFailModeConnectors {
		if got := cfg.EffectiveHookFailModeForConnector(name); got != "closed" {
			t.Errorf("standalone %s hook fail mode = %q, want closed", name, got)
		}
		if got := cfg.EffectiveActionHookFailModeForConnector(name); got != "closed" {
			t.Errorf("standalone %s action hook fail mode = %q, want closed", name, got)
		}
	}
}

// Secure Client keeps its configured fail modes (only its native Codex and
// Claude Code hooks are pinned closed), and per-user installs keep theirs.
func TestSecureClientAndPerUserKeepConfiguredHookFailModes(t *testing.T) {
	for _, test := range []struct {
		name, mode, profile string
		want                map[string]string
	}{
		{"secure client", managed.DeploymentModeManagedEnterprise, managed.ProfileSecureClient,
			map[string]string{"amp": "open", "kiro": "open", "cursor": "open", "codex": "closed", "claudecode": "closed"}},
		{"per-user", "", "",
			map[string]string{"amp": "open", "kiro": "open", "cursor": "open", "codex": "open", "claudecode": "open"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := managedFailOpenConfig(test.mode, test.profile)
			if cfg.ManagedHooksFailClosed() {
				t.Fatal("ManagedHooksFailClosed() = true")
			}
			for name, want := range test.want {
				if got := cfg.EffectiveHookFailModeForConnector(name); got != want {
					t.Errorf("%s hook fail mode = %q, want %q", name, got, want)
				}
			}
			if got := cfg.ManagedFailOpenWarnings(); got != nil {
				t.Errorf("ManagedFailOpenWarnings() = %q, want none", got)
			}
		})
	}
}

// Each ignored open value is named once, in a stable order, with the reason.
func TestManagedFailOpenWarningsNameEachIgnoredSetting(t *testing.T) {
	cfg := managedFailOpenConfig(managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone)
	const hookWhy = ": open is ignored on this managed computer: outside Secure Client every DefenseClaw hook fails closed, so a call DefenseClaw cannot check is blocked"
	want := []string{
		"guardrail.hook_fail_mode" + hookWhy,
		"guardrail.connectors.amp.hook_fail_mode" + hookWhy,
		"guardrail.connectors.kiro.hook_fail_mode" + hookWhy,
		"application_protection.connectors.hermes.guardrail.hook_fail_mode" + hookWhy,
		"acp.profiles.watch.fail_mode: open is ignored on this managed computer: outside Secure Client the ACP guard refuses a step DefenseClaw cannot check, in observe mode too",
	}
	if got := cfg.ManagedFailOpenWarnings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ManagedFailOpenWarnings() =\n%q\nwant\n%q", got, want)
	}
	cfg.Guardrail.HookFailMode = "closed"
	cfg.Guardrail.Connectors = nil
	cfg.ApplicationProtection.Connectors = nil
	cfg.ACP.Profiles = nil
	if got := cfg.ManagedFailOpenWarnings(); got != nil {
		t.Fatalf("closed config warnings = %q, want none", got)
	}
}
