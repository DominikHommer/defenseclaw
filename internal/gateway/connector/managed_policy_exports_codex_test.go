// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// GAP-0008/GAP-0101: managed Codex requirements on Linux and macOS bound
// every command to codex-hooks-v4 but registered the older ten-event matrix,
// without compact at SessionStart and without SessionEnd.
func TestManagedCodexUnversionedMatrixMatchesTheBoundContract(t *testing.T) {
	contract := ResolveHookContract("codex", "").Contract
	for _, goos := range []string{"linux", "darwin"} {
		groups, err := ManagedHookGroupsForOS("codex", "", goos)
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != len(contract.Events) {
			t.Fatalf("%s: %d groups, contract %s has %d events", goos, len(groups), contract.ContractID, len(contract.Events))
		}
		byEvent := map[string]ManagedHookGroup{}
		for i, group := range groups {
			if group.Event != contract.Events[i] {
				t.Fatalf("%s: group %d is %s, contract event is %s", goos, i, group.Event, contract.Events[i])
			}
			byEvent[group.Event] = group
		}
		if byEvent["SessionStart"].Matcher != "startup|resume|clear|compact" {
			t.Fatalf("%s: SessionStart matcher = %q", goos, byEvent["SessionStart"].Matcher)
		}
		if end, ok := byEvent["SessionEnd"]; !ok || end.Timeout != codexSessionEndHookGroup.timeout {
			t.Fatalf("%s: SessionEnd = %+v (registered %v)", goos, end, ok)
		}
	}

	// Windows keeps the matrix its machine-requirements installer verifies.
	windows, err := ManagedHookGroupsForOS("codex", "", "windows")
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != len(codexHookGroups) {
		t.Fatalf("windows: %d groups, want %d", len(windows), len(codexHookGroups))
	}
}
