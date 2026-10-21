// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package unixidentity

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of r104 W2B, loop 5. A local account's facts need every directory
// service after files to show that it holds no other account of the uid
// (loop 4). While SSSD is stopped, nslcd cannot reach LDAP, or the service
// is NIS (whose miss getent cannot show), that proof is unavailable. The
// lookup then failed with nothing else, and the failed lookup selected
// default_profile, weaker than the profile the account's /etc/group
// membership selected before the proof. The lookup still fails, but says
// whose facts they are if the directory holds nothing more, so the gateway
// can refuse instead of using a weaker default.
func TestUnprovenOwnershipNamesTheLocalCandidate(t *testing.T) {
	dir := t.TempDir()
	oldPasswd, oldGroup, oldNSS, oldSSSD, oldSocket, oldNSLCD := localPasswdPath, localGroupPath, nsswitchPath, sssdConfPath, sssdNSSSocket, nslcdSockets
	t.Cleanup(func() {
		localPasswdPath, localGroupPath, nsswitchPath, sssdConfPath, sssdNSSSocket, nslcdSockets = oldPasswd, oldGroup, oldNSS, oldSSSD, oldSocket, oldNSLCD
	})
	localPasswdPath, localGroupPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), filepath.Join(dir, "nsswitch.conf")
	sssdConfPath, sssdNSSSocket = filepath.Join(dir, "sssd.conf"), filepath.Join(dir, "no-sssd", "nss")
	nslcdSockets = []string{filepath.Join(dir, "no-nslcd", "socket")}
	const entry = "opsadmin:x:1001:1001::/home/opsadmin:/bin/bash\n"
	write := func(path, data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(localPasswdPath, entry)
	write(localGroupPath, "opsadmin:x:1001:\nstrict-devs:x:5100:opsadmin\n")
	write(sssdConfPath, "[sssd]\ndomains = corp.example.com\n")
	results := map[string]commandResult{
		"passwd 1001":          {stdout: []byte(entry)},
		"-s files passwd 1001": {stdout: []byte(entry)},
	}
	unproven := func(t *testing.T, f *fakeRun) *UnprovenFactsError {
		t.Helper()
		facts, err := newFakeNSS(f).DirectoryFactsForUID(1001, time.Now())
		var candidate *UnprovenFactsError
		if err == nil || !errors.As(err, &candidate) {
			t.Fatalf("facts = %+v, %v; want the lookup to fail with the local candidate", facts, err)
		}
		if !facts.ResolvedAt.IsZero() {
			t.Fatalf("an unproven lookup served facts %+v", facts)
		}
		return candidate
	}
	for _, tc := range []struct {
		name, nss string
		errs      map[string]error
	}{
		{name: "SSSD stopped after files", nss: "passwd: files sss\ngroup: files sss\n"},
		{name: "SSSD does not answer for the uid", nss: "passwd: files sss\ngroup: files sss\n",
			errs: map[string]error{"-s sss passwd 1001": errors.New("getent timed out")}},
		{name: "SSSD stopped before files", nss: "passwd: sss files\ngroup: sss files\n"},
		{name: "healthy NIS without the uid", nss: "passwd: files nis\ngroup: files nis\n"},
		{name: "nslcd cannot reach LDAP", nss: "passwd: files ldap\ngroup: files ldap\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(nsswitchPath, tc.nss)
			got := unproven(t, &fakeRun{results: results, errs: tc.errs}).Candidate
			if got.Directory != useridentity.DirectoryLocal || got.ResolvedAt.IsZero() ||
				!slices.Contains(got.Groups, "strict-devs") || !slices.Contains(got.Groups, "opsadmin") {
				t.Fatalf("candidate = %+v; want the local account in strict-devs", got)
			}
		})
	}

	// Errors that prove something carry no candidate: the guardian's spool
	// lookup (no groups, nothing to select a profile with), and a uid two
	// /etc/passwd entries hold, whether SSSD answers or not.
	write(nsswitchPath, "passwd: files sss\ngroup: files sss\n")
	var candidate *UnprovenFactsError
	if _, err := newFakeNSS(&fakeRun{results: results}).DirectoryFactsWithoutGroupsForUID(1001, time.Now()); err == nil || errors.As(err, &candidate) {
		t.Fatalf("spool lookup: err = %v; want a plain failure", err)
	}
	write(localPasswdPath, entry+"opsclone:x:1001:1001::/home/opsclone:/bin/bash\n")
	if _, err := newFakeNSS(&fakeRun{results: results}).DirectoryFactsForUID(1001, time.Now()); err == nil || errors.As(err, &candidate) {
		t.Fatalf("shared uid, SSSD stopped: err = %v; want a failure without a candidate", err)
	}
	startFakeSSSD(t, nil)
	_, err := newFakeNSS(&fakeRun{results: results}).DirectoryFactsForUID(1001, time.Now())
	var shared *SharedUIDError
	if !errors.As(err, &shared) || errors.As(err, &candidate) {
		t.Fatalf("shared uid, SSSD answering: err = %v; want a SharedUIDError without a candidate", err)
	}

	// Control: SSSD answers, so the proof holds and the facts are served.
	write(localPasswdPath, entry)
	facts, err := newFakeNSS(&fakeRun{results: results}).DirectoryFactsForUID(1001, time.Now())
	if err != nil || facts.Directory != useridentity.DirectoryLocal || !slices.Contains(facts.Groups, "strict-devs") {
		t.Fatalf("facts with SSSD answering = %+v, %v", facts, err)
	}
}
