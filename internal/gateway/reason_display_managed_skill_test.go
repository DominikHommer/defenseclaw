// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// GAP-0758: a managed Windows standard user was told to run `defenseclaw
// skill info <name>`, a command that managed computer does not give them.
// Elsewhere the hint stays.
func TestReasonDisabledSkillHintFitsTheManagedWindowsUser(t *testing.T) {
	previousGOOS, previousManaged := reasonDisplayGOOS, managedEnterpriseActive.Load()
	t.Cleanup(func() {
		reasonDisplayGOOS = previousGOOS
		managedEnterpriseActive.Store(previousManaged)
	})
	const reason = "ASSET-POLICY reason_code=runtime-disable source=runtime-disable asset_type=skill asset_name=deploy-helper"
	for _, tc := range []struct {
		goos    string
		managed bool
		info    bool
	}{
		{"windows", true, false},
		{"windows", false, true},
		{"linux", true, true},
	} {
		reasonDisplayGOOS = tc.goos
		managedEnterpriseActive.Store(tc.managed)
		got := agentAssetPolicySubject(reason)
		if !strings.HasPrefix(got, "skill deploy-helper is disabled by security policy") {
			t.Fatalf("%s managed=%v: %q", tc.goos, tc.managed, got)
		}
		if strings.Contains(got, "defenseclaw skill info") != tc.info {
			t.Fatalf("%s managed=%v: %q, want skill info hint %v", tc.goos, tc.managed, got, tc.info)
		}
	}
}
