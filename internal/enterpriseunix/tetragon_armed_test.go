// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

// GAP-0166: a user enforce is loaded for, with no running agent session
// anchored, reads armed in status, verify and the fleet phase, and is never
// counted as enforced; it is still ready, so the host stays ready for enforce.
func TestArmedUserIsNotCalledEnforced(t *testing.T) {
	state, why := userStateWords(TetragonUser{UID: 1001, State: kernelpolicy.UIDArmed}, burnInProgress{Ready: true})
	if state != "armed" || why == "" {
		t.Fatalf("status words = %q, %q", state, why)
	}
	if got := enforcedUsers([]kernelpolicy.UIDStatus{{UID: 1001, State: kernelpolicy.UIDArmed}}); got != 0 {
		t.Fatalf("enforced users = %d, want 0", got)
	}
	armed := TetragonUserReadiness{UID: 1001, User: "alice", State: kernelpolicy.UIDArmed, Ready: true}
	if got := userPhase(armed, true); got != phaseArmed {
		t.Fatalf("phase = %q, want armed", got)
	}
	want := "enforce is loaded for every enrolled user (1); 0 are enforced and 1 is armed with no running agent session anchored yet."
	if got := enforceCounts([]TetragonUserReadiness{armed}, false); got != want {
		t.Fatalf("counts = %q\nwant     %q", got, want)
	}
	enforcing := TetragonUserReadiness{UID: 1000, User: "root2", State: kernelpolicy.UIDEnforcing, Ready: true}
	if got := enforceCounts([]TetragonUserReadiness{enforcing}, false); got != "every enrolled user (1) is enforced." {
		t.Fatalf("counts with an anchored session = %q", got)
	}
}
