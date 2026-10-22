// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Managed Windows Kiro resolves to its reviewed contract, which still covers
// the kiro-cli builds 1.0.3 enrolled so those rows keep being repaired. The
// standalone profile enrolls, and follows a version change to, only
// KiroCLIHookFloor and later, as the not-gated floor does on Unix.
func TestStandaloneKiroCLIFloorRefusalGatesTheManagedWindowsContract(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	for raw, refused := range map[string]bool{
		"2.24.1":                         true,
		"kiro-cli 2.26.1":                true,
		"2.27.1":                         false,
		"2.30.0":                         false,
		"1.0.190" + KiroIDEVersionSuffix: false, // the IDE has its own contract floor
	} {
		resolution := connector.ResolveWindowsManagedKiroHookContract(raw)
		if resolution.Status != connector.HookCompatibilityKnown {
			t.Fatalf("fixture %s must resolve to a managed contract: %s (%s)", raw, resolution.Status, resolution.Reason)
		}
		reason := standaloneKiroCLIFloorRefusal(resolution)
		if refused != (reason != "") || (refused && !strings.Contains(reason, "is below 2.27.1")) {
			t.Fatalf("%s refusal = %q, want refused=%t", raw, reason, refused)
		}
		if accepted := standaloneAcceptsAgentVersionChange(resolution); accepted == refused {
			t.Fatalf("%s version change accepted = %t, want %t", raw, accepted, !refused)
		}
	}
	// Every other resolution is gated elsewhere.
	if reason := standaloneKiroCLIFloorRefusal(connector.ResolveHookContract("kiro", "2.22.0")); reason != "" {
		t.Fatalf("not-gated Kiro refused here: %s", reason)
	}
	if reason := standaloneKiroCLIFloorRefusal(connector.ResolveHookContract("codex", "0.140.0")); reason != "" {
		t.Fatalf("codex refused: %s", reason)
	}
}
