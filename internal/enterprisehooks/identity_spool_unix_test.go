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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestIdentitySpoolKeepsRecordsOfAccountsAPassDidNotList pins GAP-0145 and
// GAP-1113: a successful pass removes the record of a local account it no
// longer lists (excluded, out of the manifest or deleted), which nothing
// would refresh again, so status and verify warned identity_records_stale
// about it; it keeps a directory account's record while no directory account
// resolved (the pass could not decide it while the directory was
// unreachable) and the gateway still trusts it. A failed pass removes no
// young record; a record older than IdentitySpoolMaxAge goes.
func TestIdentitySpoolKeepsRecordsOfAccountsAPassDidNotList(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		record IdentitySpoolRecord
		age    time.Duration
	}{
		{IdentitySpoolRecord{Key: "94401103", User: "dcad-bob", SSSDDomain: "dclab.test", Facts: useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryActiveDirectory, Realm: "DCLAB.TEST",
		}}, 5 * time.Minute},
		{IdentitySpoolRecord{Key: "94401104", User: "dave"}, 2 * IdentitySpoolMaxAge},
		{IdentitySpoolRecord{Key: "94401106", User: "carol", Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal}}, 5 * time.Minute},
	} {
		data, err := MarshalIdentitySpoolRecord(tc.record)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, tc.record.Key+".json")
		if err := os.WriteFile(path, data, 0o640); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-tc.age)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(key string) bool {
		_, err := os.Stat(filepath.Join(dir, key+".json"))
		return err == nil
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WriteIdentitySpool(canceled, dir, []IdentitySpoolAccount{{UID: 94401107, User: "erin"}}, nil, nil); err == nil {
		t.Fatal("the canceled lookup did not fail the pass")
	}
	if !exists("94401103") || !exists("94401106") || exists("94401104") {
		t.Fatalf("after a failed pass: directory %v, local %v, expired %v; want the young records kept and the expired one gone",
			exists("94401103"), exists("94401106"), exists("94401104"))
	}
	if err := WriteIdentitySpool(context.Background(), dir, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !exists("94401103") {
		t.Error("the record of an unlisted directory account was removed while no directory account resolved")
	}
	if exists("94401106") {
		t.Error("the record of a local account the pass no longer lists was kept")
	}
	const reassigned = "94401105"
	data, err := MarshalIdentitySpoolRecord(IdentitySpoolRecord{
		Key: reassigned, User: "alice", UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, reassigned+".json")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	// The canceled lookup fails and the pass reports it; the record of the
	// previous owner must be gone either way.
	_ = WriteIdentitySpool(canceled, dir, []IdentitySpoolAccount{{UID: 94401105, User: "bob"}}, nil, nil)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("reassigned uid kept previous account record: %v", err)
	}
}

// A successful refresh of one SSSD domain cannot establish that a missing
// account from another SSSD domain left enrollment.
func TestIdentitySpoolCleanupRequiresTheRecordsDomainToAnswer(t *testing.T) {
	dir := t.TempDir()
	for _, record := range []IdentitySpoolRecord{
		{Key: "94401103", User: "alice", SSSDDomain: "unreachable.test",
			Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, UPN: "alice@unreachable.test"}},
		{Key: "94401104", User: "bob", SSSDDomain: "reachable.test",
			Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, UPN: "bob@reachable.test"}},
	} {
		data, err := MarshalIdentitySpoolRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	answered := map[string]bool{"sssd:reachable.test": true}
	for _, entry := range entries {
		got, directory := identitySpoolRecordLeft(dir, entry, answered)
		want := entry.Name() == "94401104.json"
		if got != want || !directory {
			t.Errorf("cleanup %s = %v (directory %v), want %v (directory true)", entry.Name(), got, directory, want)
		}
	}
}

// stubIdentitySpoolLookupUID answers the departure lookup: the uids in
// present resolve to their names, any other uid is not found.
func stubIdentitySpoolLookupUID(t *testing.T, present map[int]string) {
	t.Helper()
	previous := identitySpoolLookupUID
	t.Cleanup(func() { identitySpoolLookupUID = previous })
	identitySpoolLookupUID = func(uid int) (unixidentity.Account, error) {
		if name, ok := present[uid]; ok {
			return unixidentity.Account{Name: name, UID: uid}, nil
		}
		return unixidentity.Account{}, unixidentity.ErrNotFound
	}
}

// GAP-1236: one account of a directory resolving does not show that another
// account of it, which the pass did not list, left: its lookup may have
// missed once. The record stays until a second successive pass that also
// does not list it, and a pass that lists it again starts over.
func TestIdentitySpoolKeepsAnOmittedAccountOfAnAnsweringDirectoryUntilASecondPass(t *testing.T) {
	stubIdentitySpoolLookupUID(t, nil) // bob's uid no longer resolves
	dir := t.TempDir()
	directoryRecord := func(uid int, user string) IdentitySpoolRecord {
		return IdentitySpoolRecord{Key: strconv.Itoa(uid), User: user, UpdatedAt: time.Now().UTC(), SSSDDomain: "dclab.test",
			Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Realm: "DCLAB.TEST"}}
	}
	previous := identitySpoolCollect
	t.Cleanup(func() { identitySpoolCollect = previous })
	identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, _ time.Time) (IdentitySpoolRecord, error) {
		return directoryRecord(account.UID, account.User), nil
	}
	alice := IdentitySpoolAccount{UID: 94401201, User: "dcad-alice"}
	bob := IdentitySpoolAccount{UID: 94401202, User: "dcad-bob"}
	data, err := MarshalIdentitySpoolRecord(directoryRecord(bob.UID, bob.User))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "94401202.json"), data, 0o640); err != nil {
		t.Fatal(err)
	}
	for pass, step := range []struct {
		accounts []IdentitySpoolAccount
		wantBob  bool
	}{
		{[]IdentitySpoolAccount{alice}, true},      // bob's lookup missed once
		{[]IdentitySpoolAccount{alice, bob}, true}, // and recovered
		{[]IdentitySpoolAccount{alice}, true},      // a new first omission
		{[]IdentitySpoolAccount{alice}, false},     // confirmed: bob is gone
	} {
		if err := WriteIdentitySpool(context.Background(), dir, step.accounts, nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "94401202.json")); (err == nil) != step.wantBob {
			t.Fatalf("pass %d: bob's record present = %v, want %v", pass+1, err == nil, step.wantBob)
		}
	}
}

// GAP-0284: a record that resolved no UPN (a signed-out Windows user) keeps
// the account's last known UPN and principal instead of account@REALM.
func TestIdentitySpoolKeepsTheLastKnownUPN(t *testing.T) {
	const sid = "S-1-5-21-1111-2222-3333-1105"
	previous := IdentitySpoolRecord{Key: sid, UPNSource: UPNSourceTranslateName, Facts: useridentity.DirectoryFacts{
		Principal: "dcad-alice@dclab.test", UPN: "dcad-alice@dclab.test", Domain: "dclab.test", Realm: "DCLAB.TEST",
	}}
	signedOut := IdentitySpoolRecord{Key: sid, Facts: useridentity.DirectoryFacts{
		Principal: useridentity.AccountPrincipal("dcad-alice", "DCLAB.TEST"), Realm: "DCLAB.TEST",
	}}
	got := KeepLastKnownUPN(signedOut, previous)
	if got.Facts.UPN != "dcad-alice@dclab.test" || got.Facts.Principal != "dcad-alice@dclab.test" ||
		got.UPNSource != UPNSourceTranslateName {
		t.Fatalf("record = %+v, want the last known UPN", got)
	}
	if other := KeepLastKnownUPN(IdentitySpoolRecord{Key: "S-1-5-21-1111-2222-3333-1106"}, previous); other.Facts.UPN != "" {
		t.Fatalf("another account took the UPN: %+v", other)
	}
}

// TestIdentitySpoolKeepsAnInfoPipeUPNThroughAnAnswerWithoutIt: InfoPipe
// answering without userPrincipalName (the [ifp] user_attributes lost it) is
// not a verified change, so the record keeps the UPN it verified before, for
// the same account in the same SSSD domain only (GAP-1114).
func TestIdentitySpoolKeepsAnInfoPipeUPNThroughAnAnswerWithoutIt(t *testing.T) {
	previous := IdentitySpoolRecord{Key: "94403999", User: "dcad-w4a2@dclab.test", SSSDDomain: "dclab.test", UPNSource: UPNSourceInfoPipe,
		Facts: useridentity.DirectoryFacts{UPN: "w4a2.alt@alt.dclab.test", Principal: "w4a2.alt@alt.dclab.test", Source: useridentity.SourceSSSDInfoPipe}}
	derived := IdentitySpoolRecord{Key: "94403999", User: "dcad-w4a2@dclab.test", SSSDDomain: "dclab.test", UPNSource: UPNSourceDerived,
		Facts: useridentity.DirectoryFacts{Principal: "dcad-w4a2@DCLAB.TEST", Source: useridentity.SourceSSSD}}
	got, kept := KeepVerifiedInfoPipeUPN(derived, previous)
	if !kept || got.Facts.UPN != "w4a2.alt@alt.dclab.test" || got.Facts.Principal != got.Facts.UPN || got.UPNSource != UPNSourceInfoPipeKept {
		t.Fatalf("record = %+v, want the verified UPN kept", got)
	}
	moved := derived
	moved.SSSDDomain = "other.test"
	if got, kept := KeepVerifiedInfoPipeUPN(moved, previous); kept || got.Facts.UPN != "" {
		t.Fatalf("an account InfoPipe holds in another domain kept the UPN: %+v", got)
	}
}

// GAP-1235: a UPN InfoPipe stopped reporting was carried into every later
// record, so a UPN removed in the directory kept selecting the account's
// UPN profile for as long as the guardian ran. It is kept for
// IdentitySpoolKeptUPNMaxAge from the first pass that kept it, and the
// GAP-1114 carry-forward still holds inside that bound.
func TestIdentitySpoolKeepsAnInfoPipeUPNOnlyForADay(t *testing.T) {
	start := time.Date(2026, 10, 13, 6, 0, 0, 0, time.UTC)
	previous := IdentitySpoolRecord{Key: "94403999", User: "dcad-w4a2@dclab.test", SSSDDomain: "dclab.test", UPNSource: UPNSourceInfoPipe,
		UpdatedAt: start.Add(-time.Minute),
		Facts:     useridentity.DirectoryFacts{UPN: "w4a2.alt@alt.dclab.test", Principal: "w4a2.alt@alt.dclab.test", Source: useridentity.SourceSSSDInfoPipe}}
	pass := func(at time.Time) IdentitySpoolRecord {
		return IdentitySpoolRecord{Key: "94403999", User: "dcad-w4a2@dclab.test", SSSDDomain: "dclab.test", UPNSource: UPNSourceDerived,
			UpdatedAt: at, Facts: useridentity.DirectoryFacts{Principal: "dcad-w4a2@DCLAB.TEST", Source: useridentity.SourceSSSD}}
	}
	first, kept := KeepVerifiedInfoPipeUPN(pass(start), previous)
	if !kept || first.Facts.UPN != "w4a2.alt@alt.dclab.test" || !first.UPNKeptSince.Equal(start) {
		t.Fatalf("first pass without the UPN = %+v, want it kept since %s", first, start)
	}
	// The record goes through the spool file between passes.
	data, err := MarshalIdentitySpoolRecord(first)
	if err != nil {
		t.Fatal(err)
	}
	if first, err = ParseIdentitySpoolRecord(data, "94403999"); err != nil {
		t.Fatal(err)
	}
	later, kept := KeepVerifiedInfoPipeUPN(pass(start.Add(23*time.Hour)), first)
	if !kept || later.Facts.UPN == "" || !later.UPNKeptSince.Equal(start) {
		t.Fatalf("a pass inside the bound = %+v, want the UPN kept since %s", later, start)
	}
	gone, kept := KeepVerifiedInfoPipeUPN(pass(start.Add(IdentitySpoolKeptUPNMaxAge)), later)
	if kept || gone.Facts.UPN != "" || gone.UPNSource != UPNSourceDerived || !gone.UPNKeptSince.IsZero() {
		t.Fatalf("a pass a day after InfoPipe dropped the UPN = %+v, want the derived record", gone)
	}
	// A kept record an older build wrote (no UPNKeptSince) starts the bound now.
	legacy := later
	legacy.UPNKeptSince = time.Time{}
	if got, kept := KeepVerifiedInfoPipeUPN(pass(start.Add(30*time.Hour)), legacy); !kept || !got.UPNKeptSince.Equal(start.Add(30*time.Hour)) {
		t.Fatalf("a legacy kept record = %+v, want the bound to start at this pass", got)
	}
}

// A lookup failure must reach the guardian so its next pass uses the short
// retry interval rather than treating partial directory facts as refreshed.
func TestIdentitySpoolReportsFailedAccount(t *testing.T) {
	err := WriteIdentitySpool(context.Background(), t.TempDir(),
		[]IdentitySpoolAccount{{UID: 999999999, User: ""}}, nil, nil)
	if err == nil {
		t.Fatal("failed account lookup was reported as a successful spool pass")
	}
}

// GAP-0921: the gateway trusts a record by its wall-clock age, so a clock
// step forward (records look hours old) or back (records dated in the future)
// makes the records stale, and the guardian rewrites them at its next tick.
func TestIdentitySpoolStaleAfterAClockStep(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "94401103.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, tc := range []struct {
		written time.Time
		stale   bool
	}{{now.Add(-5 * time.Minute), false}, {now.Add(-2 * time.Hour), true}, {now.Add(2 * time.Hour), true}} {
		if err := os.Chtimes(path, tc.written, tc.written); err != nil {
			t.Fatal(err)
		}
		if _, _, stale := IdentitySpoolStale(dir, now, 17*time.Minute); stale != tc.stale {
			t.Errorf("record written %s from now: stale = %v, want %v", tc.written.Sub(now).Round(time.Minute), stale, tc.stale)
		}
	}
	if _, _, stale := IdentitySpoolStale(t.TempDir(), now, 17*time.Minute); stale {
		t.Error("an empty spool is not stale")
	}
}

// One account can stop refreshing while another still succeeds. Status must
// notice the account whose gateway record will age out.
func TestIdentitySpoolStaleWhenOneAccountStopsRefreshing(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for name, age := range map[string]time.Duration{
		"1001.json": 2 * time.Hour,
		"1002.json": 5 * time.Minute,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		written := now.Add(-age)
		if err := os.Chtimes(path, written, written); err != nil {
			t.Fatal(err)
		}
	}
	oldest, key, stale := IdentitySpoolStale(dir, now, 30*time.Minute)
	if !stale || now.Sub(oldest) < time.Hour || key != "1001" {
		t.Fatalf("oldest record = %s (%q), stale = %v; want the stale account reported", oldest, key, stale)
	}
}

// GAP-1116: a record dated in the future is the account named when it alone
// makes the spool stale; an over-age record is still named first.
func TestIdentitySpoolStaleNamesTheFutureDatedRecord(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		ages    map[string]time.Duration
		wantKey string
	}{
		{map[string]time.Duration{"1001": -10 * time.Minute, "1002": 0}, "1001"},
		{map[string]time.Duration{"1001": -10 * time.Minute, "1002": 0, "1003": 2 * time.Hour}, "1003"},
	} {
		dir := t.TempDir()
		for key, age := range tc.ages {
			path := filepath.Join(dir, key+".json")
			if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			written := now.Add(-age)
			if err := os.Chtimes(path, written, written); err != nil {
				t.Fatal(err)
			}
		}
		when, key, stale := IdentitySpoolStale(dir, now, 5*time.Minute)
		if !stale || key != tc.wantKey || !when.Equal(now.Add(-tc.ages[tc.wantKey])) {
			t.Fatalf("records %v: stale = %v, key %q at %s; want %q", tc.ages, stale, key, when, tc.wantKey)
		}
	}
}

// GAP-1075: a macOS record dscl returned by short name is refused unless its
// UniqueID is the uid the enumerator resolves: another account's verified
// identity must not be spooled under this uid.
func TestMacOSRecordOfAnotherAccountIsRefused(t *testing.T) {
	if err := checkMacOSRecordUID("UniqueID: 501\nAuthenticationAuthority: ;Kerberosv5;;alice@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM;\n", 501); err != nil {
		t.Fatalf("the account's own record was refused: %v", err)
	}
	err := checkMacOSRecordUID("UniqueID: 1404012345\nAltSecurityIdentities: PlatformSSO:alice@contoso.example\n", 501)
	if err == nil || !strings.Contains(err.Error(), "record belongs to another account") {
		t.Fatalf("another account's record was accepted: %v", err)
	}
	if err := checkMacOSRecordUID("AuthenticationAuthority: ;ShadowHash;\n", 501); err == nil {
		t.Fatal("a record without a UniqueID was accepted")
	}
}

// W2B-G-enum review: a directory listing can omit an account on every pass
// while another account of the directory resolves (SSSD enumerate=false, a
// partial answer). Two such passes removed the omitted account's fresh
// record, and a profile assigned by its UPN fell to the default. The record
// now stays while the account's own uid still resolves to it, until it ages
// out; it goes once the uid stops resolving or names another account, and at
// once for an account the enrollment settings leave out.
func TestIdentitySpoolKeepsAnAccountPartialListingsOmitWhileItResolves(t *testing.T) {
	dir := t.TempDir()
	directoryRecord := func(uid int, user string) IdentitySpoolRecord {
		return IdentitySpoolRecord{Key: strconv.Itoa(uid), User: user, UpdatedAt: time.Now().UTC(), SSSDDomain: "dclab.test",
			Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Realm: "DCLAB.TEST", UPN: user + "@dclab.test"}}
	}
	previous := identitySpoolCollect
	t.Cleanup(func() { identitySpoolCollect = previous })
	identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, _ time.Time) (IdentitySpoolRecord, error) {
		return directoryRecord(account.UID, account.User), nil
	}
	present := map[int]string{94401302: "dcad-bob", 94401303: "dcad-carol"}
	stubIdentitySpoolLookupUID(t, present)
	alice := IdentitySpoolAccount{UID: 94401301, User: "dcad-alice"}
	for _, record := range []IdentitySpoolRecord{directoryRecord(94401302, "dcad-bob"), directoryRecord(94401303, "dcad-carol")} {
		data, err := MarshalIdentitySpoolRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	has := func(key string) bool {
		_, err := os.Stat(filepath.Join(dir, key+".json"))
		return err == nil
	}
	pass := func(accounts ...IdentitySpoolAccount) {
		t.Helper()
		if err := WriteIdentitySpool(context.Background(), dir, accounts, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 4 {
		pass(alice)
		if !has("94401302") || !has("94401303") {
			t.Fatalf("partial listing %d removed a record of an account that still resolves: bob %v, carol %v", i+1, has("94401302"), has("94401303"))
		}
	}
	// carol's uid now names another account; bob's still resolves.
	present[94401303] = "dcad-dave"
	pass(alice)
	if has("94401303") || !has("94401302") {
		t.Fatalf("after carol's uid was reassigned: carol %v, bob %v; want carol's record gone and bob's kept", has("94401303"), has("94401302"))
	}
	// bob's record ages out while every listing still omits him.
	old := time.Now().Add(-IdentitySpoolMaxAge - time.Minute)
	if err := os.Chtimes(filepath.Join(dir, "94401302.json"), old, old); err != nil {
		t.Fatal(err)
	}
	pass(alice)
	if has("94401302") {
		t.Fatal("the record of an account the listings omit outlived its maximum age")
	}
	// An account the enrollment settings leave out goes at once, also while
	// it resolves.
	erin := IdentitySpoolAccount{UID: 94401305, User: "dcad-erin"}
	present[erin.UID] = erin.User
	pass(alice, erin)
	if !has("94401305") {
		t.Fatal("erin's record was not published")
	}
	pass(alice, IdentitySpoolAccount{UID: erin.UID, Left: true})
	if has("94401305") {
		t.Fatal("the record of an account the enrollment leaves out was kept")
	}
}
