// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package unixidentity

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of r104 W2B, loop round 3. With "passwd: nis sss", getent names an
// SSSD account in strict-devs, but the per-service NIS lookup of its uid
// times out. passwdOwner returned that as a plain failure: no candidate, so
// the gateway applied default_profile, weaker than the strict profile
// rel/1.0.4 gave the account (it asked only the directory services). A
// service before the owner that does not answer, whatever it is, now leaves
// the lookup unproven, with the candidate the later service's account
// gives; a candidate pass that fails too leaves it unproven with none.
func TestAServiceThatDoesNotAnswerBeforeTheOwnerLeavesTheLookupUnproven(t *testing.T) {
	const uid = 41401
	line := []byte("carol:*:41401:41401::/home/carol:/bin/bash\n")
	results := func() map[string]commandResult {
		return map[string]commandResult{
			"passwd 41401": {stdout: line}, "-s sss passwd 41401": {stdout: line},
			"initgroups carol": {stdout: []byte("carol 41401 5100\n")},
			"group 5100 41401": {stdout: []byte("strict-devs:*:5100:\ncarol:*:41401:\n")},
		}
	}
	timedOut := errors.New("signal: killed (getent timed out)")
	for _, tc := range []struct {
		name, nss, service string
		err                error // the service's getent error, or
		exit               int   // its exit code
	}{
		{name: "NIS times out", nss: "passwd: nis sss\ngroup: sss\ninitgroups: sss\n", service: "nis", err: timedOut},
		{name: "NIS fails", nss: "passwd: nis sss\ngroup: sss\ninitgroups: sss\n", service: "nis", exit: 1},
		{name: "NIS+ times out", nss: "passwd: nisplus sss\ngroup: sss\n", service: "nisplus", err: timedOut},
		{name: "a module DefenseClaw has no check for fails", nss: "passwd: altdb sss\ngroup: sss\n", service: "altdb", exit: 1},
		{name: "LDAP's getent times out", nss: "passwd: ldap sss\ngroup: sss\n", service: "ldap", err: timedOut},
		{name: "winbind's getent times out", nss: "passwd: winbind sss\ngroup: sss\n", service: "winbind", err: timedOut},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accountHost(t, "root:x:0:0::/root:/bin/sh\n", "", tc.nss)
			startFakeSSSD(t, nil)
			f := &fakeRun{results: results(), errs: map[string]error{}}
			key := "-s " + tc.service + " passwd 41401"
			if tc.err != nil {
				f.errs[key] = tc.err
			} else {
				f.results[key] = commandResult{exitCode: tc.exit}
			}
			facts, err := newFakeNSS(f).DirectoryFactsForUID(uid, time.Now())
			var unproven *UnprovenFactsError
			if !errors.As(err, &unproven) || !unproven.HasCandidate() || !facts.ResolvedAt.IsZero() {
				t.Fatalf("facts = %+v, %v; want the lookup unproven with a candidate", facts, err)
			}
			if got := unproven.Candidate; got.Source != useridentity.SourceSSSD || !slices.Contains(got.Groups, "strict-devs") {
				t.Fatalf("candidate = %+v; want the SSSD account in strict-devs", got)
			}

			// The candidate pass fails too: still unproven, without a
			// candidate, never a plain failure.
			f.errs["initgroups carol"] = timedOut
			_, err = newFakeNSS(f).DirectoryFactsForUID(uid, time.Now())
			unproven = nil
			if !errors.As(err, &unproven) || unproven.HasCandidate() {
				t.Fatalf("candidate pass failing: err = %v; want the lookup unproven without a candidate", err)
			}
		})
	}

	// Control: every service answers, so the facts are proved and served.
	t.Run("the service before the owner answers", func(t *testing.T) {
		accountHost(t, "root:x:0:0::/root:/bin/sh\n", "", "passwd: winbind sss\ngroup: sss\n")
		startFakeSSSD(t, nil)
		facts, err := newFakeNSS(&fakeRun{results: results()}).DirectoryFactsForUID(uid, time.Now())
		if err != nil || facts.Source != useridentity.SourceSSSD || !slices.Contains(facts.Groups, "strict-devs") {
			t.Fatalf("facts = %+v, %v; want the SSSD account in strict-devs", facts, err)
		}
	})
}
