// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// until 1.1: guard the removal while older configs may still carry these IDs.
func TestRemovedConnectorsUnavailable(t *testing.T) {
	registry := NewDefaultRegistry()
	for _, name := range []string{"openhands", "omnigent"} {
		if IsKnownBuiltinConnector(name) {
			t.Errorf("%s is still a built-in connector", name)
		}
		if _, found := registry.Get(name); found {
			t.Errorf("%s is still in the default registry", name)
		}
	}
}
