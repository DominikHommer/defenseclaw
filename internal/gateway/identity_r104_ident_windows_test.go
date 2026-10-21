// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import "testing"

// GAP-1183: a qualified filter for a deleted directory account lists only
// SIDs of the domain it names.
func TestRemovedAccountFilterKeepsWindowsDomainsApart(t *testing.T) {
	previous := windowsSIDDomainName
	windowsSIDDomainName = func(sid string) string {
		return map[string]string{"S-1-5-21-1-2-3-1201": "CORP", "S-1-5-21-9-8-7-1201": "OTHER"}[sid]
	}
	t.Cleanup(func() { windowsSIDDomainName = previous })
	if !adminViewDomainCouldHold(`CORP\alice`, "S-1-5-21-1-2-3-1201") {
		t.Fatal("the deleted CORP account is not listed by CORP\\alice")
	}
	if adminViewDomainCouldHold(`CORP\alice`, "S-1-5-21-9-8-7-1201") {
		t.Fatal("the deleted OTHER account is listed by CORP\\alice")
	}
	if adminViewDomainCouldHold(`CORP\alice`, "S-1-5-21-5-5-5-1201") {
		t.Fatal("a SID of a domain the LSA does not name is listed by CORP\\alice")
	}
}
