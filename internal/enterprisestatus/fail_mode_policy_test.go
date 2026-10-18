// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"reflect"
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

// rel-1-0-3 GAP-0037: status, ensure and verify list on a standalone
// deployment the resolved hook fail mode of each protected connector, so an
// administrator can read that observe-mode Kiro and Cursor fail closed.
func TestFailModePolicyListsEachConnectorsResolvedMode(t *testing.T) {
	r := New("status", "standalone", "linux", "1.0.3")
	r.AddFailModePolicyWarnings(failOpenObserveConfig(managed.ProfileStandalone), []string{"cursor", "kiro"})
	if want := map[string]string{"cursor": "closed", "kiro": "closed"}; !reflect.DeepEqual(r.HookFailModes, want) {
		t.Fatalf("HookFailModes = %v, want %v", r.HookFailModes, want)
	}
	if len(r.Warnings) == 0 || r.Warnings[0].Code != CodeFailOpenIgnored {
		t.Fatalf("warnings = %v, want a %s warning", r.Warnings, CodeFailOpenIgnored)
	}
	document, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(document), `"hook_fail_modes":{"cursor":"closed","kiro":"closed"}`) {
		t.Fatalf("status JSON %s does not list hook_fail_modes", document)
	}

	sc := New("status", "secure-client", "linux", "1.0.3")
	sc.AddFailModePolicyWarnings(failOpenObserveConfig(managed.ProfileSecureClient), []string{"cursor", "kiro"})
	if sc.HookFailModes != nil || len(sc.Warnings) != 0 {
		t.Fatalf("Secure Client: HookFailModes = %v, warnings = %v, want neither", sc.HookFailModes, sc.Warnings)
	}
}
