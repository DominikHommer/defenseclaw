//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0014: status reports the fail mode the pinned guardian renders for the
// profile the loaded config resolves, whatever the caller's own profile pin.
// An unpinned administrator shell reading a standalone install sees closed
// for every standalone per-user connector and for Codex, Claude Code and
// Cursor; a Secure Client install keeps its own resolution even from a
// standalone-pinned process: the native Codex and Claude Code hooks closed
// and an observe-mode connector without a value of its own open. Copilot
// reports the closed runtime the guardian writes for it
// (windowsRuntimeOnlyRuntimeFailMode), as the live dcw-std1 .hookcfg showed.
// Outside Secure Client Hermes is closed too: its managed hook blocks through
// Hermes' block directive (rel-1-0-3 GAP-0037).
func TestWindowsManagedHookFailModeFollowsTheConfigProfile(t *testing.T) {
	for _, tc := range []struct {
		profile string
		pin     string
		want    map[string]string
	}{
		{managed.ProfileStandalone, "", map[string]string{
			"codex": "closed", "claudecode": "closed", "cursor": "closed",
			"opencode": "closed", "copilot": "closed", "amp": "closed", "hermes": "closed",
		}},
		{managed.ProfileStandalone, managed.ProfileStandalone, map[string]string{
			"codex": "closed", "opencode": "closed", "amp": "closed", "copilot": "closed", "hermes": "closed",
		}},
		{managed.ProfileSecureClient, managed.ProfileStandalone, map[string]string{
			"codex": "closed", "claudecode": "closed", "opencode": "open",
		}},
	} {
		t.Run(tc.profile+"/pin="+tc.pin, func(t *testing.T) {
			t.Setenv(managed.EnterpriseProfileEnv, tc.pin)
			cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
			cfg.Enterprise.Profile = tc.profile
			cfg.Guardrail.Mode = "observe"
			cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"amp": {HookFailMode: "open"}}
			for name, want := range tc.want {
				if got := ManagedHookFailMode(cfg, name); got != want {
					t.Errorf("%s: ManagedHookFailMode = %q, want %q", name, got, want)
				}
			}
		})
	}
	if got := ManagedHookFailMode(nil, "codex"); got != "closed" {
		t.Errorf("a config that resolves no profile reports %q, want closed", got)
	}
}
