// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of r104 W2B, loop round 2. With "passwd: files sss", a local
// account in /etc/group's strict-devs and a lenient default, a lookup whose
// SSSD probe outlasts the request's wait left no candidate yet, so the
// request got the lenient default. The local candidate now exists from the
// lookup's start. A uid more than one account holds left no candidate at
// all and fell to the default; it is now kept as an ambiguity that refuses.
func TestALookupThatHasNotProvedTheAccountNeverAppliesAWeakerDefault(t *testing.T) {
	setUnprovenFacts(t, nil)
	set, err := newGuardrailProfileSet(unprovenProfileConfig(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	prevLocal, prevNSS := peerLocalCandidate, peerNSSFacts
	t.Cleanup(func() { peerLocalCandidate, peerNSSFacts = prevLocal, prevNSS })
	localIn := func(groups ...string) func(int, time.Time) (string, useridentity.DirectoryFacts, bool, error) {
		return func(_ int, now time.Time) (string, useridentity.DirectoryFacts, bool, error) {
			return "opsadmin", useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles,
				Assurance: useridentity.AssuranceVerified, ResolvedAt: now, Groups: groups}, true, nil
		}
	}
	noLocal := func(int, time.Time) (string, useridentity.DirectoryFacts, bool, error) {
		return "", useridentity.DirectoryFacts{}, false, nil
	}
	// lookup makes the NSS half block until release says how it ends.
	lookup := func() (started chan struct{}, release chan error) {
		started, release = make(chan struct{}), make(chan error)
		peerNSSFacts = func(string) (useridentity.DirectoryFacts, error) {
			close(started)
			if err := <-release; err != nil {
				return useridentity.DirectoryFacts{}, err
			}
			return useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles,
				Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(), Groups: []string{"opsadmin", "strict-devs"}}, nil
		}
		return started, release
	}
	decide := func(uid, connector string, subject *profileSubject) profileDecision {
		if subject == nil {
			s := unprovenSubject(uid)
			subject = &s
		}
		return set.match(subject, profileSubjectVerified, connector, "")
	}
	wantRefused := func(t *testing.T, got profileDecision, why string) {
		t.Helper()
		if got.Refused == "" || !strings.Contains(got.Refused, why) || got.Name != "lenient" || got.Match != profileMatchDefaultLookupFailed {
			t.Fatalf("decision = %+v; want a refusal that says %q", got, why)
		}
	}
	wantDefault := func(t *testing.T, got profileDecision) {
		t.Helper()
		if got.Refused != "" || got.Name != "lenient" {
			t.Fatalf("decision = %+v; want the default, not refused", got)
		}
	}

	t.Run("a request that stops waiting for a slow lookup is refused", func(t *testing.T) {
		setUnprovenFacts(t, nil)
		peerLocalCandidate = localIn("opsadmin", "strict-devs")
		started, release := lookup()
		cache := newIdentityDirectoryCache(resolvePeerDirectoryFacts)
		if _, ok := cache.get("1001", true); ok {
			t.Fatal("the cache answered before the lookup ended")
		}
		<-started
		wantRefused(t, decide("1001", "cursor", nil), "has not answered yet")
		release <- nil
		if _, ok := cache.get("1001", true); !ok {
			t.Fatal("the lookup did not resolve")
		}
		wantDefault(t, decide("1001", "cursor", nil))
	})

	t.Run("the candidate is named by its local entry when the request carries no name", func(t *testing.T) {
		cfg := unprovenProfileConfig()
		cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Users: []string{`.\opsadmin`}}}}
		byName, err := newGuardrailProfileSet(cfg, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		entry := localCandidate(time.Now(), "opsadmin")
		nameless := unprovenSubject("1001")
		nameless.UserName = ""
		setUnprovenFacts(t, map[string]unprovenFactsEntry{"1001": entry})
		if got := byName.match(&nameless, profileSubjectVerified, "cursor", ""); got.Refused != "" {
			t.Fatalf("a candidate without a name = %+v; want the default (nothing names it)", got)
		}
		entry.name = "opsadmin"
		setUnprovenFacts(t, map[string]unprovenFactsEntry{"1001": entry})
		if got := byName.match(&nameless, profileSubjectVerified, "cursor", ""); got.Refused == "" || got.Name != "lenient" {
			t.Fatalf("a candidate named opsadmin = %+v; want refused (its name selects strict)", got)
		}
	})

	for _, tc := range []struct {
		name    string
		local   func(int, time.Time) (string, useridentity.DirectoryFacts, bool, error)
		end     error
		refused string // "" for the default
	}{
		{name: "a local candidate whose profile is the default's", local: localIn("opsadmin")},
		{name: "two /etc/passwd names at the uid, before the lookup ends", refused: "more than one account holds",
			local: func(int, time.Time) (string, useridentity.DirectoryFacts, bool, error) {
				return "", useridentity.DirectoryFacts{}, false, &unixidentity.SharedUIDError{UID: 1001, Accounts: []string{"opsadmin (files)", "opsclone (files)"}}
			}},
		{name: "a lookup that ends with a shared uid", local: localIn("opsadmin"), refused: "more than one account holds",
			end: &unixidentity.SharedUIDError{UID: 1001, Accounts: []string{"opsadmin (files)", "corp.example.com\\opsadmin (sss)"}}},
		{name: "a shared uid with no local entry", local: noLocal, refused: "more than one account holds",
			end: &unixidentity.SharedUIDError{UID: 1001, Accounts: []string{"a (ldap)", "b (ldap)"}}},
		{name: "a lookup that fails another way keeps the local candidate", local: localIn("opsadmin", "strict-devs"),
			end: errors.New("getent: signal: killed"), refused: "uid 1001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setUnprovenFacts(t, nil)
			peerLocalCandidate = tc.local
			started, release := lookup()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = resolvePeerDirectoryFacts("1001")
			}()
			<-started
			if tc.end == nil {
				// While the lookup runs.
				if tc.refused == "" {
					wantDefault(t, decide("1001", "cursor", nil))
				} else {
					wantRefused(t, decide("1001", "cursor", nil), tc.refused)
				}
				release <- errors.New("still down")
				<-done
				return
			}
			release <- tc.end
			<-done
			if tc.refused == "" {
				wantDefault(t, decide("1001", "cursor", nil))
			} else {
				wantRefused(t, decide("1001", "cursor", nil), tc.refused)
			}
		})
	}

	t.Run("a failure without a local entry keeps the outage default", func(t *testing.T) {
		setUnprovenFacts(t, nil)
		peerLocalCandidate = noLocal
		_, release := lookup()
		go func() { release <- errors.New("sssd: no reply") }()
		if _, err := resolvePeerDirectoryFacts("1001"); err == nil {
			t.Fatal("the lookup did not fail")
		}
		wantDefault(t, decide("1001", "cursor", nil))
	})

	t.Run("a retry replaces a candidate past the facts lifetime", func(t *testing.T) {
		setUnprovenFacts(t, map[string]unprovenFactsEntry{"1001": localCandidate(time.Now().Add(-identityDirectoryTTL-time.Second), "opsadmin")})
		peerLocalCandidate = localIn("opsadmin", "strict-devs")
		started, release := lookup()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = resolvePeerDirectoryFacts("1001")
		}()
		<-started
		wantRefused(t, decide("1001", "cursor", nil), "has not answered yet")
		release <- nil
		<-done
	})

	t.Run("a retry does not replace the candidate of the lookup before", func(t *testing.T) {
		before := localCandidate(time.Now(), "opsadmin", "strict-devs", "ldap-auditors")
		setUnprovenFacts(t, map[string]unprovenFactsEntry{"1001": before})
		peerLocalCandidate = localIn("opsadmin", "strict-devs")
		started, release := lookup()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = resolvePeerDirectoryFacts("1001")
		}()
		<-started
		unprovenFacts.Lock()
		during := unprovenFacts.entries["1001"]
		unprovenFacts.Unlock()
		if !slices.Contains(during.facts.Groups, "ldap-auditors") || during.reason != before.reason {
			t.Fatalf("candidate during the retry = %+v; want the earlier lookup's", during)
		}
		release <- nil
		<-done
		unprovenFacts.Lock()
		_, kept := unprovenFacts.entries["1001"]
		unprovenFacts.Unlock()
		if kept {
			t.Fatal("a resolved lookup kept its candidate")
		}
	})
}
