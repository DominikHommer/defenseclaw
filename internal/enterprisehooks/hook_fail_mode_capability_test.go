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
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ManagedHookFailMode is the value the renderer writes. Under Secure Client a
// connector whose agent cannot fail closed (Hermes, Copilot) gets an open hook
// even when the config resolves closed, so status must not say closed
// (GAP-0001). Outside Secure Client every connector's managed hooks block
// through the native deny, so status says closed for every connector,
// configured open included (rel-1-0-3 GAP-0037).
func TestManagedHookFailModeIsTheRenderedValue(t *testing.T) {
	newCfg := func(profile string) *config.Config {
		cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
		cfg.Enterprise.Profile = profile
		closed := config.PerConnectorGuardrailConfig{HookFailMode: "closed"}
		cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
			"hermes": closed, "copilot": closed, "opencode": closed, "amp": {HookFailMode: "open"},
		}
		return cfg
	}
	for _, tc := range []struct {
		profile string
		want    map[string]string
	}{
		{managed.ProfileSecureClient, map[string]string{
			"hermes": "open", "copilot": "open", // cannot fail closed
			"codex": "closed", "claudecode": "closed", "opencode": "closed",
			"amp": "open", // configured open stays open
		}},
		{managed.ProfileStandalone, map[string]string{
			"hermes": "closed", "copilot": "closed",
			"codex": "closed", "claudecode": "closed", "opencode": "closed",
			"amp": "closed",
		}},
	} {
		cfg := newCfg(tc.profile)
		for _, name := range []string{"hermes", "copilot"} {
			if got := cfg.EffectiveHookFailModeForConnector(name); got != "closed" {
				t.Fatalf("%s %s: the config resolves %q; the test needs closed", tc.profile, name, got)
			}
		}
		if runtime.GOOS == "windows" {
			// The Windows renderer pins every standalone per-user connector closed
			// whatever the config says (windowsEnterpriseHookFailMode).
			tc.want["amp"] = "closed"
		}
		for name, mode := range tc.want {
			if got := ManagedHookFailMode(cfg, name); got != mode {
				t.Errorf("%s %s: ManagedHookFailMode = %q, the renderer writes %q", tc.profile, name, got, mode)
			}
		}
		if got := renderedHookFailModeFor(cfg, "not-a-connector", "closed"); got != "closed" {
			t.Errorf("%s: unknown connector = %q", tc.profile, got)
		}
	}
}
