// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedConfigForProfile returns a managed-enterprise config on profile, and
// pins this process to the same profile: on Windows the renderer reads the
// process's protected profile pin (windowsEnterpriseStandaloneProcess), not
// the config. A config with no profile resolves to Secure Client.
func managedConfigForProfile(t *testing.T, profile string) *config.Config {
	t.Helper()
	pin := ""
	if profile == managed.ProfileStandalone {
		pin = profile
	}
	t.Setenv(managed.EnterpriseProfileEnv, pin)
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = profile
	return cfg
}

// ManagedHookFailMode is the value the renderer writes. Outside Secure Client
// every connector's managed hooks block through the native deny, so status
// says closed for every connector, configured open included (rel-1-0-3
// GAP-0037), and managed Codex and Claude Code hooks always fail closed.
func TestManagedHookFailModeIsTheRenderedValue(t *testing.T) {
	cfg := managedConfigForProfile(t, managed.ProfileStandalone)
	closed := config.PerConnectorGuardrailConfig{HookFailMode: "closed"}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"hermes": closed, "copilot": closed, "opencode": closed, "amp": {HookFailMode: "open"},
	}
	for _, name := range []string{"hermes", "copilot"} {
		if got := cfg.EffectiveHookFailModeForConnector(name); got != "closed" {
			t.Fatalf("%s: the config resolves %q; the test needs closed", name, got)
		}
	}
	want := map[string]string{
		"hermes": "closed", "copilot": "closed",
		"codex": "closed", "claudecode": "closed", "opencode": "closed",
		"amp": "closed", // configured open is ignored outside Secure Client
	}
	for name, mode := range want {
		if got := ManagedHookFailMode(cfg, name); got != mode {
			t.Errorf("%s: ManagedHookFailMode = %q, the renderer writes %q", name, got, mode)
		}
	}
	if got := renderedHookFailModeFor(cfg, "not-a-connector", "closed"); got != "closed" {
		t.Errorf("unknown connector = %q", got)
	}
}

// Under Secure Client a connector whose agent cannot fail closed (Hermes,
// Copilot) gets an open hook even when the config resolves closed, so status
// must not say closed (GAP-0001). The native Codex and Claude Code hooks stay
// closed, and an unset mode does not open (the #1163 unset-is-open default is
// not taken in 1.0.3).
func TestSecureClientManagedHookFailModeFollowsTheConfig(t *testing.T) {
	cfg := managedConfigForProfile(t, managed.ProfileSecureClient)
	if !cfg.SecureClientIntegration() {
		t.Fatal("the test needs the Secure Client profile")
	}
	closed := config.PerConnectorGuardrailConfig{HookFailMode: "closed"}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"hermes": closed, "copilot": closed, "opencode": closed, "amp": {HookFailMode: "open"},
	}
	want := map[string]string{
		"hermes": "open", "copilot": "open", // cannot fail closed
		"codex": "closed", "claudecode": "closed", "opencode": "closed",
		"amp": "open", // configured open stays open
	}
	for name, mode := range want {
		if got := ManagedHookFailMode(cfg, name); got != mode {
			t.Errorf("%s: ManagedHookFailMode = %q, want %q", name, got, mode)
		}
	}
	if got := renderedHookFailModeFor(cfg, "not-a-connector", "closed"); got != "closed" {
		t.Errorf("unknown connector = %q", got)
	}
}
