// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-1263: a qualified --user filter for a deleted account lists only the
// uid the gateway knew in that domain, not a deleted namesake of another.
func TestRemovedAccountFilterKeepsDomainsApart(t *testing.T) {
	const east, west, unknown = "3999001", "3999002", "3999003"
	previous := managedHookPeerLastName
	managedHookPeerLastName = func(uid int) string {
		return map[int]string{3999001: "alice@east.example", 3999002: "alice@west.example"}[uid]
	}
	t.Cleanup(func() { managedHookPeerLastName = previous })
	for _, tc := range []struct {
		filter, id string
		want       bool
	}{
		{"alice@east.example", east, true},
		{"alice@east.example", west, false},
		{"alice@EAST.EXAMPLE", east, true},
		{"alice@west.example", west, true},
		{"alice@east.example", unknown, false},
	} {
		if got := adminViewDomainCouldHold(tc.filter, tc.id); got != tc.want {
			t.Errorf("adminViewDomainCouldHold(%q, %s) = %v, want %v", tc.filter, tc.id, got, tc.want)
		}
	}
}

// GAP-0551: during a directory outage, the UPN and DOMAIN\name spellings
// explain accepts find the facts the hooks cached for the account.
func TestProfileExplainDuringOutageAcceptsEverySpelling(t *testing.T) {
	const uid = 1_870_400_551
	const name = "alice"
	accounts := map[int]unixidentity.Account{uid: {Name: name, UID: uid, Home: "/home/" + name}}
	previous, previousFacts := managedHookPeerHomes, identityFactsEnabled.Load()
	managedHookPeerHomes = &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver { return &fakePeerHomeResolver{accounts: accounts} },
		now:         time.Now,
	}
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { managedHookPeerHomes = previous; setIdentityFactsEnabled(previousFacts) })
	facts := useridentity.DirectoryFacts{
		Domain: "corp.example", AccountDomain: "CORP", Realm: "CORP.EXAMPLE", UPN: "alice.smith@corp.example",
		Principal: "alice.smith@corp.example", Groups: []string{"engineering"}, ResolvedAt: time.Now(),
	}
	managedHookPeerHomes.directoriesOnce.Do(func() {
		managedHookPeerHomes.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) { return facts, nil })
	})
	if _, ok := managedHookPeerHomes.directory(uid, true); !ok {
		t.Fatal("the hook path did not cache the facts")
	}
	for _, spelled := range []string{"alice.smith@corp.example", `CORP\alice`, "alice@corp.example", "1870400551"} {
		subject, err := profileExplainUnresolved(spelled, unixidentity.ErrNotFound)
		if err != nil || subject.UserID != "1870400551" || subject.cachedFactsAge <= 0 {
			t.Fatalf("explain %s during the outage = %+v, %v; want the cached facts", spelled, subject, err)
		}
	}
	if subject, err := profileExplainUnresolved(`OTHER\alice`, unixidentity.ErrNotFound); err == nil && subject.UserID == "1870400551" {
		t.Fatalf("another domain's spelling found the cached account: %+v", subject)
	}
}
