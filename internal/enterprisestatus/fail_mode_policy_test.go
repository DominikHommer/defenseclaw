// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func failOpenObserveConfig(profile string) *config.Config {
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = profile
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.HookFailMode = "open"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"kiro":   {Mode: "observe"},
		"cursor": {Mode: "observe"},
	}
	return cfg
}

// rel-1-0-3 GAP-0037: ensure, status and verify name each fail-open setting
// a standalone deployment ignores with the fail_open_ignored code; Secure
// Client keeps the configured fail mode and gets no warning. The resolved
// fail mode of each connector is in the status v2 connectors block
// (TestManagedHookFailModeIsTheRenderedValue).
func TestFailModePolicyNamesEachIgnoredFailOpenSetting(t *testing.T) {
	r := New("status", "standalone", "linux", "1.0.3")
	r.AddFailModePolicyWarnings(failOpenObserveConfig(managed.ProfileStandalone))
	if len(r.Warnings) == 0 || r.Warnings[0].Code != CodeFailOpenIgnored {
		t.Fatalf("warnings = %v, want a %s warning", r.Warnings, CodeFailOpenIgnored)
	}
	document, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(document), "hook_fail_modes") {
		t.Fatalf("status JSON %s still carries hook_fail_modes", document)
	}

	sc := New("status", "secure-client", "linux", "1.0.3")
	sc.AddFailModePolicyWarnings(failOpenObserveConfig(managed.ProfileSecureClient))
	if len(sc.Warnings) != 0 {
		t.Fatalf("Secure Client: warnings = %v, want none", sc.Warnings)
	}
}
