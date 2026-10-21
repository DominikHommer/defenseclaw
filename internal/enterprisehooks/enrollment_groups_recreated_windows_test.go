// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// testRecreatedGroupSID is the SID of a group recreated under the name of
// testDomainGroupSID's group.
const testRecreatedGroupSID = "S-1-5-21-111111111-222222222-333333333-1207"

// stubRecreatedGroupDirectory answers group name lookups with answer(name):
// a SID, an error, or a call that blocks until release is called (stuck).
// It shortens the lookup waits and drains the lookups still running at
// cleanup.
func stubRecreatedGroupDirectory(t *testing.T, answer func(name string) (sid string, err error, stuck bool)) (release func()) {
	t.Helper()
	held := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(held) }) }
	previousResolve, previousMembers, previousMachine := windowsResolveGroupName, windowsLocalGroupDirectMembers, windowsMachineAccountDomainSID
	previousTimeout, previousLimit := windowsGroupNameLookupTimeout, windowsGroupNameLookupCycleLimit
	t.Cleanup(func() {
		release()
		waitIdentityLookupGateIdle(t, &windowsGroupNameLookupGate)
		windowsResolveGroupName, windowsLocalGroupDirectMembers, windowsMachineAccountDomainSID = previousResolve, previousMembers, previousMachine
		windowsGroupNameLookupTimeout, windowsGroupNameLookupCycleLimit = previousTimeout, previousLimit
	})
	windowsGroupNameLookupTimeout, windowsGroupNameLookupCycleLimit = 30*time.Millisecond, 200*time.Millisecond
	windowsMachineAccountDomainSID = func() (string, error) { return testMachineDomainSID, nil }
	windowsLocalGroupDirectMembers = func(string) ([]string, error) { return nil, errors.New("not a local group") }
	var mu sync.Mutex
	windowsResolveGroupName = func(name string) (string, error) {
		mu.Lock()
		sid, err, stuck := answer(name)
		mu.Unlock()
		if stuck {
			<-held
			return "", errors.New("the lookup was abandoned")
		}
		return sid, err
	}
	return release
}

// W2B-G-enum review loop 3: an exclude_groups name kept the SID cached when
// it last resolved whenever its lookup timed out, was still running from an
// earlier cycle, or failed. A group deleted and recreated under the same
// name has another SID, so a user whose token holds the new SID was judged
// not excluded and the enumerator published their row despite the
// exclusion; an include_groups name could likewise revoke a member of the
// recreated group. A name that does not resolve this cycle now keeps its
// cached SID only for the users it lists: a decision that rests on a user
// not being in it is pending until the name resolves again.
func TestWindowsGroupNameThatDoesNotResolveNowKeepsNoExclusionOfARecreatedGroup(t *testing.T) {
	for _, failure := range []struct {
		name  string
		stuck bool
		err   error
	}{
		{name: "lookup never returns", stuck: true},
		{name: "directory unreachable", err: errors.New("the domain controller is unreachable")},
		{name: "name not mapped while offline", err: windows.ERROR_NONE_MAPPED},
	} {
		t.Run(failure.name, func(t *testing.T) {
			var mu sync.Mutex
			state := "old"
			setState := func(next string) { mu.Lock(); state = next; mu.Unlock() }
			release := stubRecreatedGroupDirectory(t, func(string) (string, error, bool) {
				mu.Lock()
				defer mu.Unlock()
				switch state {
				case "old":
					return testDomainGroupSID, nil, false
				case "new":
					return testRecreatedGroupSID, nil, false
				}
				return "", failure.err, failure.stuck
			})
			exclude := []string{`CONTOSO\Contractors`}
			cache := NewWindowsEnrollmentGroupCache()
			first := newWindowsEnrollmentGroups(nil, exclude, map[string][]string{testDomainUserA: {}}, nil, cache, nil)
			if got, reason := first.decide(testDomainUserA); got != windowsEnrollmentEnrolled {
				t.Fatalf("before the change: %d (%s), want enrolled", got, reason)
			}
			if cache.Names[`contoso\contractors`] != testDomainGroupSID {
				t.Fatalf("names cached %v, want the old SID", cache.Names)
			}

			// The group is deleted and recreated under its name; the user's
			// new token holds the new SID, and the lookup does not answer.
			// Two cycles: a stuck lookup is still running at the second.
			setState("failing")
			recreated := map[string][]string{testDomainUserA: {testRecreatedGroupSID}}
			for cycle := 1; cycle <= 2; cycle++ {
				groups := newWindowsEnrollmentGroups(nil, exclude, recreated, nil, cache, nil)
				if got, reason := groups.decide(testDomainUserA); got != windowsEnrollmentUndecided || !strings.Contains(reason, "did not resolve this cycle") {
					t.Fatalf("cycle %d: member of the recreated group: %d (%s), want pending, never enrolled", cycle, got, reason)
				}
				// A user the cached SID lists is still excluded.
				old := newWindowsEnrollmentGroups(nil, exclude, map[string][]string{testDomainUserB: {testDomainGroupSID}}, nil, cache, nil)
				if got, reason := old.decide(testDomainUserB); got != windowsEnrollmentExcluded {
					t.Fatalf("cycle %d: holder of the cached SID: %d (%s), want excluded", cycle, got, reason)
				}
				// A local account is not decided on the unverified SID either.
				local := newWindowsEnrollmentGroups(nil, exclude, map[string][]string{testLocalUserSID: {}}, nil, cache, nil)
				if got, reason := local.decide(testLocalUserSID); got != windowsEnrollmentUndecided {
					t.Fatalf("cycle %d: local account: %d (%s), want pending", cycle, got, reason)
				}
				if cache.Names[`contoso\contractors`] != testDomainGroupSID {
					t.Fatalf("cycle %d: the cached SID was dropped: %v", cycle, cache.Names)
				}
			}

			// include_groups: a member of the recreated group is not revoked.
			cache.Names[`contoso\developers`] = testDomainDevelopersSID
			includes := newWindowsEnrollmentGroups([]string{`CONTOSO\Developers`}, nil,
				map[string][]string{testDomainUserA: {"S-1-5-21-111111111-222222222-333333333-1208"}}, nil, cache, nil)
			if got, reason, inDoubt := includes.evaluate(testDomainUserA); got != windowsEnrollmentExcluded || !inDoubt {
				t.Fatalf("include of a recreated group: %d (%s) in doubt %v, want a non-member decision in doubt", got, reason, inDoubt)
			}
			if got, _ := includes.decide(testDomainUserA); got != windowsEnrollmentUndecided {
				t.Fatalf("include of a recreated group: %d, want pending, never excluded", got)
			}

			// Once the name resolves again, its new SID decides.
			setState("new")
			release()
			waitIdentityLookupGateIdle(t, &windowsGroupNameLookupGate)
			groups := newWindowsEnrollmentGroups(nil, exclude, recreated, nil, cache, nil)
			if got, reason := groups.decide(testDomainUserA); got != windowsEnrollmentExcluded {
				t.Fatalf("after the name resolves again: %d (%s), want excluded", got, reason)
			}
			if cache.Names[`contoso\contractors`] != testRecreatedGroupSID {
				t.Fatalf("names cached %v, want the new SID", cache.Names)
			}
		})
	}
}

// The enumerator and the eligibility walk end to end: the user's new token
// holds the recreated group's SID while the name does not resolve.
func TestEnumerateWindowsPublishesNoRowOnTheCachedSIDOfAnUnresolvedExcludeGroup(t *testing.T) {
	stubMachineWinGet(t, nil)
	previousActive, previousSignedIn := windowsActiveSessionGroups, windowsSignedInSessionUsers
	t.Cleanup(func() { windowsActiveSessionGroups, windowsSignedInSessionUsers = previousActive, previousSignedIn })
	windowsActiveSessionGroups, windowsSignedInSessionUsers = readWindowsActiveSessionGroups, readWindowsSignedInSessionUsers
	for _, tc := range []struct {
		name         string
		resolves     bool
		cached       bool
		rows         bool
		wantRows     string
		wantExcluded string
		wantPending  bool
		wantEligible int
	}{
		{name: "no row: none is published", cached: true, wantPending: true},
		{name: "an existing row is kept, never revoked", cached: true, rows: true, wantRows: testDomainUserA},
		{name: "control: the name resolves to the new SID", resolves: true, cached: true, rows: true, wantExcluded: testDomainUserA},
		{name: "control: a name never resolved excludes no one", wantRows: testDomainUserA, wantEligible: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubRecreatedGroupDirectory(t, func(string) (string, error, bool) {
				if tc.resolves {
					return testRecreatedGroupSID, nil, false
				}
				return "", errors.New("the domain controller is unreachable"), false
			})
			stubWindowsSessionAPI(t, []windowsSession{{id: 1, state: windows.WTSActive}}, map[uint32]string{1: testDomainUserA}, nil, nil)
			stubWindowsSessionTokenGroups(map[uint32][]string{1: {testRecreatedGroupSID}}, nil)
			home := codexProfile(t, "0.150.0")
			injectWindowsProfileList(t, map[string]string{testDomainUserA: home})
			enabled := true
			var rows []ManifestTarget
			if tc.rows {
				rows = append(rows, ManifestTarget{SID: testDomainUserA, Connector: "codex", UserHome: home, DataDir: home + `\.defenseclaw`, AgentVersion: "0.150.0", Enabled: &enabled})
			}
			newCache := func() *WindowsEnrollmentGroupCache {
				cache := NewWindowsEnrollmentGroupCache()
				cache.Users[testDomainUserA] = []string{}
				if tc.cached {
					cache.Names[`contoso\contractors`] = testDomainGroupSID
				}
				return cache
			}
			eligible, err := WindowsStandaloneEligibleProfilesFor(context.Background(), EnumerateOptions{
				ExcludeGroups: []string{`CONTOSO\Contractors`}, GroupCache: newCache(),
			})
			if err != nil || len(eligible) != tc.wantEligible {
				t.Fatalf("eligible profiles %+v (%v), want %d", eligible, err, tc.wantEligible)
			}
			var excluded []string
			pending := 0
			manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
				ExistingManifestPath: writeWindowsTestManifest(t, rows...),
				ExcludeGroups:        []string{`CONTOSO\Contractors`},
				GroupCache:           newCache(),
				ReportExcluded:       func(target ManifestTarget) { excluded = append(excluded, target.SID) },
				ReportUnprotected: func(agent UnprotectedAgent) {
					if strings.Contains(agent.Reason, "pending") {
						pending++
					}
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := manifestSIDs(manifest); got != tc.wantRows {
				t.Fatalf("rows for %q, want %q", got, tc.wantRows)
			}
			if got := strings.Join(excluded, ","); got != tc.wantExcluded {
				t.Fatalf("excluded %q, want %q", got, tc.wantExcluded)
			}
			if tc.wantPending && pending != 1 {
				t.Fatalf("pending reports %d, want 1: the signed-in user can run the agent", pending)
			}
		})
	}
}
