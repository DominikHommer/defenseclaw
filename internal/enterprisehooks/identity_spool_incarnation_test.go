// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of GAP-0551 (loop 2): a UPN SSSD InfoPipe stopped reporting is kept
// for the same account incarnation only, once the previous record names one:
// a uid handed to another account of the same name in the same SSSD domain
// (deleted and created again with another SID) does not inherit the first
// account's UPN for a day. A previous record an older guardian wrote names
// none and is kept as before.
func TestKeepVerifiedInfoPipeUPNNeedsTheSameIncarnation(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	previous := IdentitySpoolRecord{Key: "5000", User: "alice", SSSDDomain: "corp.example", AccountIncarnation: "sid:S-1-5-21-1-1-1-500",
		UPNSource: UPNSourceInfoPipe, UpdatedAt: now.Add(-15 * time.Minute),
		Facts: useridentity.DirectoryFacts{UPN: "alice@corp.example", Principal: "alice@corp.example"}}
	fresh := IdentitySpoolRecord{Key: "5000", User: "alice", SSSDDomain: "corp.example", AccountIncarnation: "sid:S-1-5-21-1-1-1-501",
		UpdatedAt: now}
	if got, kept := KeepVerifiedInfoPipeUPN(fresh, previous); kept || got.Facts.UPN != "" {
		t.Fatalf("record of another incarnation = %+v, kept %v; want no UPN carried over", got, kept)
	}
	fresh.AccountIncarnation = previous.AccountIncarnation
	if got, kept := KeepVerifiedInfoPipeUPN(fresh, previous); !kept || got.Facts.UPN != "alice@corp.example" {
		t.Fatalf("record of the same incarnation = %+v, kept %v; want the UPN kept", got, kept)
	}
	previous.AccountIncarnation = ""
	if _, kept := KeepVerifiedInfoPipeUPN(fresh, previous); !kept {
		t.Fatal("a previous record without an incarnation (an older guardian) no longer keeps the UPN")
	}
}
