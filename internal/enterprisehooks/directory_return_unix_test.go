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

package enterprisehooks

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// #1197: only an enrolled Active Directory account that the system lists
// without its groups makes the caches stale, and the domain probed is that
// account's own.
func TestDirectoryCachesStaleNamesTheADAccountsDomain(t *testing.T) {
	dir := t.TempDir()
	for _, record := range []IdentitySpoolRecord{
		{Key: "501", User: "admin", Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal}},
		{Key: "94401103", User: "ent-bob", Facts: useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryActiveDirectory, Domain: "DCLab.Test"}},
		{Key: "94401104", User: "ent-ldap", Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLDAP, Domain: "ldap.example.com"}},
	} {
		data, err := MarshalIdentitySpoolRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	accounts := []IdentitySpoolAccount{{UID: 501}, {UID: 94401104}, {UID: 94401103}, {UID: 94401199}}
	listed := map[int]bool{}
	lookup := func(uid int) bool { return listed[uid] }
	// Nothing names any account: only the AD one counts.
	if domain, stale := directoryCachesStale(dir, accounts, lookup); !stale || domain != "dclab.test" {
		t.Fatalf("stale = %v %q, want the AD account's domain", stale, domain)
	}
	listed[94401103] = true
	if domain, stale := directoryCachesStale(dir, accounts, lookup); stale {
		t.Fatalf("stale with the AD account listed (domain %q): local, LDAP and unrecorded accounts do not count", domain)
	}
}

// The probe tries the domain's domain controllers from its SRV records on
// the LDAP port, falls back to the domain's own name, and refuses a name
// that is not a DNS domain without dialing.
func TestDomainControllerAnswers(t *testing.T) {
	prevSRV, prevDial := domainControllerSRV, domainControllerDial
	t.Cleanup(func() { domainControllerSRV, domainControllerDial = prevSRV, prevDial })
	var dialed []string
	up := map[string]bool{}
	domainControllerDial = func(_ context.Context, address string) error {
		dialed = append(dialed, address)
		if up[address] {
			return nil
		}
		return errors.New("connect: connection refused")
	}
	domainControllerSRV = func(_ context.Context, domain string) ([]*net.SRV, error) {
		if domain != "dclab.test" {
			return nil, errors.New("no such host")
		}
		return []*net.SRV{{Target: "dc1.dclab.test."}, {Target: "dc2.dclab.test."}}, nil
	}
	if DomainControllerAnswers(context.Background(), "DCLAB.TEST") {
		t.Fatal("answers with every domain controller away")
	}
	if !slices.Equal(dialed, []string{"dc1.dclab.test:389", "dc2.dclab.test:389"}) {
		t.Fatalf("dialed %v", dialed)
	}
	up["dc2.dclab.test:389"] = true
	if !DomainControllerAnswers(context.Background(), "dclab.test") {
		t.Fatal("dc2 answers")
	}
	dialed = nil
	up["other.example.com:389"] = true
	if !DomainControllerAnswers(context.Background(), "other.example.com") || !slices.Equal(dialed, []string{"other.example.com:389"}) {
		t.Fatalf("no SRV records: dialed %v, want the domain's own name", dialed)
	}
	dialed = nil
	for _, bad := range []string{"", "localhost", "-x.example.com", "a b.example.com", "x.example.com:389", "x..example.com"} {
		if DomainControllerAnswers(context.Background(), bad) {
			t.Fatalf("%q answered", bad)
		}
	}
	if len(dialed) != 0 {
		t.Fatalf("dialed %v for names that are not DNS domains", dialed)
	}
}
