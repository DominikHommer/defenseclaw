// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0002: a managed Config the loader never resolved reports Secure Client
// from EnterpriseProfile. An unset fail mode in action mode is closed for
// every profile, Secure Client included (the #1163 Secure Client open default
// is not taken in 1.0.3), so an unresolved profile can never open a hook.
func TestUnresolvedManagedProfileNeverOpensHooksOnLinux(t *testing.T) {
	for _, profile := range []string{"", managed.ProfileStandalone, managed.ProfileSecureClient} {
		cfg := &Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
		cfg.Enterprise.Profile = profile
		cfg.Guardrail.Mode = "action"
		for _, name := range []string{"codex", "claudecode", "opencode"} {
			if got := cfg.EffectiveHookFailModeForConnector(name); got != "closed" {
				t.Errorf("profile %q %s: unset fail mode = %q, want closed", profile, name, got)
			}
		}
	}
}
