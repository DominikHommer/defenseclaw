// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// A revoke that fails for a profile the cycle stopped enrolling is retried
// at the next cycle, though the next manifest no longer lists the profile,
// and is dropped once the profile is enrolled again (GAP-1269).
func TestEnterpriseWindowsDroppedProfileRevokeIsRetried(t *testing.T) {
	previous := enterpriseWindowsInventoryReadRevoker
	t.Cleanup(func() {
		enterpriseWindowsInventoryReadRevoker = previous
		clear(enterpriseWindowsDroppedRevokes.targets)
	})
	clear(enterpriseWindowsDroppedRevokes.targets)
	alice := enterprisehooks.ManifestTarget{SID: "S-1-5-21-1-2-3-1001", User: "alice", UserHome: `C:\Users\alice`}
	bob := enterprisehooks.ManifestTarget{SID: "S-1-5-21-1-2-3-1002", User: "bob", UserHome: `C:\Users\bob`}
	carol := enterprisehooks.ManifestTarget{SID: "S-1-5-21-1-2-3-1003", User: "carol", UserHome: `C:\Users\carol`}
	fail := true
	var calls []string
	enterpriseWindowsInventoryReadRevoker = func(dropped enterprisehooks.Manifest) error {
		var users []string
		for _, target := range dropped.Targets {
			users = append(users, target.User)
		}
		calls = append(calls, strings.Join(users, ","))
		if fail {
			return errors.New("access is denied")
		}
		return nil
	}
	current := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{alice}}
	revokeEnterpriseWindowsDroppedInventoryRead(io.Discard, enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{bob, carol}}, current)
	fail = false
	// carol is enrolled again before the retry: only bob is still owed.
	current.Targets = append(current.Targets, carol)
	revokeEnterpriseWindowsDroppedInventoryRead(io.Discard, enterprisehooks.Manifest{}, current)
	revokeEnterpriseWindowsDroppedInventoryRead(io.Discard, enterprisehooks.Manifest{}, current)
	if got := strings.Join(calls, ";"); got != "bob,carol;bob" {
		t.Fatalf("revokes = %q, want the failed pair, then bob's retry alone, then none", got)
	}
}
