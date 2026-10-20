// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A standalone managed host whose process carries the Secure Client profile
// (not pinned standalone, so secureClientHookDelivery says Secure Client)
// but that is no authenticated Secure Client deployment
// (connector.SecureClientDeploymentVerified false) stays closed: an unset
// mode does not open, and the standalone config resolves every connector
// closed (owner rule 2026-10-20, main-sync review finding 5).
func TestStandaloneHostWithSecureClientProcessProfileStaysClosed(t *testing.T) {
	useSecureClientHookDelivery(t)
	saved := connector.SecureClientDeploymentVerified
	connector.SecureClientDeploymentVerified = func() bool { return false }
	t.Cleanup(func() { connector.SecureClientDeploymentVerified = saved })
	t.Setenv(managed.EnterpriseProfileEnv, "")
	if !secureClientHookDelivery() {
		t.Fatal("test process does not carry the Secure Client profile")
	}
	if got := canonicalHookFailMode(""); got != "closed" {
		t.Fatalf("unset fail mode on an unverified host = %q, want closed", got)
	}
	if got := canonicalHookFailModeFor("", true); got != "closed" {
		t.Fatalf("unset fail mode for an explicit Secure Client profile on an unverified host = %q, want closed", got)
	}
	if got := canonicalHookFailMode("open"); got != "open" {
		t.Fatalf("an explicit open = %q, want open", got)
	}
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.HookFailMode = "open"
	for _, name := range []string{"amp", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "opencode"} {
		if got := cfg.EffectiveHookFailModeForConnector(name); got != "closed" {
			t.Errorf("%s: standalone config resolves %q, want closed", name, got)
		}
		if got := ManagedHookFailMode(cfg, name); got != "closed" {
			t.Errorf("%s: standalone ManagedHookFailMode = %q, want closed", name, got)
		}
	}
}
