// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// A Windows identity record names its account, like the Linux and macOS
// records (GAP-0025).
func TestWindowsIdentitySpoolRecordNamesTheAccount(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := strings.ToUpper(user.User.Sid.String())
	dir := t.TempDir()
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[sid] = nil
	if err := WriteWindowsIdentitySpool(context.Background(), dir, cache, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	record, err := ReadIdentitySpoolRecord(dir, sid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(record.User, `\`) {
		t.Fatalf("record user = %q, want DOMAIN\\account", record.User)
	}
}

const (
	testSpoolUserA = "S-1-5-21-111111111-222222222-333333333-4001"
	testSpoolUserB = "S-1-5-21-111111111-222222222-333333333-4002"
	testSpoolUserC = "S-1-5-21-111111111-222222222-333333333-4003"
)

// stubWindowsIdentityLookups replaces the directory lookups of a record:
// facts is called once per account in the order the pass takes them.
func stubWindowsIdentityLookups(t *testing.T, facts func(sid string), budgets *[]time.Duration) {
	t.Helper()
	previousFacts, previousNames := windowsIdentityDirectoryFacts, windowsIdentityGroupNames
	t.Cleanup(func() { windowsIdentityDirectoryFacts, windowsIdentityGroupNames = previousFacts, previousNames })
	windowsIdentityDirectoryFacts = func(sid string, _ time.Duration) useridentity.DirectoryFacts {
		if facts != nil {
			facts(sid)
		}
		return useridentity.DirectoryFacts{}
	}
	windowsIdentityGroupNames = func(sids []string, _ int, budget time.Duration) []string {
		if budgets != nil {
			*budgets = append(*budgets, budget)
		}
		return append([]string(nil), sids...)
	}
}

func writeTestIdentityRecord(t *testing.T, dir, sid string, updated time.Time) {
	t.Helper()
	data, err := MarshalIdentitySpoolRecord(IdentitySpoolRecord{Key: sid, UpdatedAt: updated})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sid+".json"), data, 0o640); err != nil {
		t.Fatal(err)
	}
}

// The identity pass obeys the enumerator cycle (GAP-1049): it stops at the
// cycle's end, keeps the records of the accounts it did not reach, and the
// next pass starts with the oldest records.
func TestWindowsIdentitySpoolStopsAtTheCycleDeadline(t *testing.T) {
	dir := t.TempDir()
	stale := time.Now().UTC().Add(-50 * time.Minute)
	writeTestIdentityRecord(t, dir, testSpoolUserA, time.Now().UTC().Add(-time.Minute))
	writeTestIdentityRecord(t, dir, testSpoolUserC, stale)
	cache := NewWindowsEnrollmentGroupCache()
	for _, sid := range []string{testSpoolUserA, testSpoolUserB, testSpoolUserC} {
		cache.Users[sid] = []string{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var order []string
	stubWindowsIdentityLookups(t, func(sid string) {
		order = append(order, sid)
		if len(order) == 2 {
			cancel() // the cycle ends while the second account is resolved
		}
	}, nil)
	err := WriteWindowsIdentitySpool(ctx, dir, cache, nil, nil, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the pass stopped by the cycle", err)
	}
	if strings.Join(order, ",") != testSpoolUserB+","+testSpoolUserC {
		t.Fatalf("resolved %v, want the account without a record, then the oldest, and none after the cycle ended", order)
	}
	record, readErr := ReadIdentitySpoolRecord(dir, testSpoolUserA, nil)
	if readErr != nil || time.Since(record.UpdatedAt) < 30*time.Second {
		t.Fatalf("the record of the account the pass did not reach = %+v (%v), want it kept unchanged", record, readErr)
	}
	for _, sid := range []string{testSpoolUserB, testSpoolUserC} {
		if record, err := ReadIdentitySpoolRecord(dir, sid, nil); err != nil || time.Since(record.UpdatedAt) > 30*time.Second {
			t.Fatalf("record of %s = %+v (%v), want it refreshed", sid, record, err)
		}
	}
}

// No lookup of a pass runs past the cycle's deadline (GAP-1049).
func TestWindowsIdentitySpoolLookupsEndWithTheCycle(t *testing.T) {
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testSpoolUserA] = []string{"S-1-5-32-545"}
	cache.SignedIn = map[string]bool{testSpoolUserA: true}
	var budgets []time.Duration
	stubWindowsIdentityLookups(t, nil, &budgets)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := WriteWindowsIdentitySpool(ctx, t.TempDir(), cache, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(budgets) != 2 {
		t.Fatalf("lookup budgets = %v, want the group names and the account name", budgets)
	}
	for _, budget := range budgets {
		if budget > 300*time.Millisecond {
			t.Fatalf("lookup budget %s runs past the cycle deadline", budget)
		}
	}
}

// An account the enrollment excluded publishes no identity record, and its
// earlier record goes (GAP-1264).
func TestWindowsIdentitySpoolPublishesNoRecordForAnExcludedAccount(t *testing.T) {
	dir := t.TempDir()
	writeTestIdentityRecord(t, dir, testSpoolUserB, time.Now().UTC())
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testSpoolUserA] = []string{"S-1-5-32-545"}
	cache.Users[testSpoolUserB] = []string{"S-1-5-32-545"}
	cache.SignedIn = map[string]bool{testSpoolUserA: true, testSpoolUserB: true}
	stubWindowsIdentityLookups(t, nil, nil)
	if err := WriteWindowsIdentitySpool(context.Background(), dir, cache, []string{strings.ToLower(testSpoolUserB)}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadIdentitySpoolRecord(dir, testSpoolUserA, nil); err != nil {
		t.Fatalf("the enrolled account's record: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, testSpoolUserB+".json")); !os.IsNotExist(err) {
		t.Fatalf("the excluded account's record is still published: %v", err)
	}
}
