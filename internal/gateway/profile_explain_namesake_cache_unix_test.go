//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func TestProfileExplainCachedNamesBindToUID(t *testing.T) {
	previous := managedHookPeerHomes
	managedHookPeerHomes = &managedHookPeerHomeCache{holders: map[int]string{
		2100:  "alex\x00/home/local",
		80001: "alex\x00/home/directory",
	}}
	t.Cleanup(func() { managedHookPeerHomes = previous })
	if uid, _, ok := managedHookPeerHomes.cachedHolder("alex"); ok {
		t.Fatalf("ambiguous cached account name selected uid %d", uid)
	}
	if uid, name, ok := managedHookPeerHomes.cachedHolder("2100"); !ok || uid != 2100 || name != "alex" {
		t.Fatalf("explicit uid selected %d, %q, %t", uid, name, ok)
	}
	local := unixidentity.Account{Name: "alex", UID: 2100}
	twins := sameNameProfileAccounts(context.Background(), nil, "alex", local)
	if len(twins) != 1 || twins[0].UID != 80001 {
		t.Fatalf("cached accounts sharing a bare name = %+v", twins)
	}
}
