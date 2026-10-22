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

// r2Fixtures points the local files, NSS and the directory sockets at a
// temporary directory: SSSD and nslcd are stopped.
func r2Fixtures(t *testing.T) func(path, data string) {
	t.Helper()
	dir := t.TempDir()
	oldPasswd, oldGroup, oldNSS, oldSSSD, oldSocket, oldNSLCD := localPasswdPath, localGroupPath, nsswitchPath, sssdConfPath, sssdNSSSocket, nslcdSockets
	t.Cleanup(func() {
		localPasswdPath, localGroupPath, nsswitchPath, sssdConfPath, sssdNSSSocket, nslcdSockets = oldPasswd, oldGroup, oldNSS, oldSSSD, oldSocket, oldNSLCD
	})
	localPasswdPath, localGroupPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), filepath.Join(dir, "nsswitch.conf")
	sssdConfPath, sssdNSSSocket = filepath.Join(dir, "sssd.conf"), filepath.Join(dir, "no-sssd", "nss")
	nslcdSockets = []string{filepath.Join(dir, "no-nslcd", "socket")}
	write := func(path, data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(localGroupPath, "opsadmin:x:1001:\nstrict-devs:x:5100:opsadmin\n")
	write(sssdConfPath, "[sssd]\ndomains = corp.example.com\n")
	return write
}

const r2Entry = "opsadmin:x:1001:1001::/home/opsadmin:/bin/bash\n"

// Review of r104 W2B, loop round 2. A request that stopped waiting for a
// slow directory had no candidate to refuse with, so a local account in a
// strict local group got the lenient default; the local candidate now comes
// from the local files alone, before any directory is asked. A uid two
// /etc/passwd entries hold is a proved shared uid, also while SSSD is
// stopped, so the gateway can refuse it rather than use the default.
func TestLocalCandidateNeedsNoDirectory(t *testing.T) {
	write := r2Fixtures(t)
	entry := r2Entry
	now := time.Now()

	// The candidate reads the local files only: SSSD is stopped here and no
	// getent runs, so a slow directory cannot delay it.
	for _, nss := range []string{"passwd: files sss\ngroup: files sss\n", "passwd: sss files\ngroup: sss files\n", "passwd: compat\npasswd_compat: sss\n"} {
		write(nsswitchPath, nss)
		for _, passwd := range []string{entry, entry + entry} {
			write(localPasswdPath, passwd)
			name, facts, ok, err := LocalCandidateForUID(1001, now)
			if err != nil || !ok || name != "opsadmin" || facts.Directory != useridentity.DirectoryLocal ||
				facts.Source != useridentity.SourceNSSFiles || !facts.ResolvedAt.Equal(now) || !slices.Contains(facts.Groups, "strict-devs") {
				t.Fatalf("%q, %q: candidate = %q %+v %t %v; want opsadmin in strict-devs", nss, passwd, name, facts, ok, err)
			}
		}
	}
	write(localPasswdPath, entry)
	if _, _, ok, err := LocalCandidateForUID(1002, now); ok || err != nil {
		t.Fatalf("uid /etc/passwd does not hold: ok=%t err=%v; want no candidate", ok, err)
	}
	write(nsswitchPath, "passwd: sss\ngroup: sss\n")
	if _, _, ok, err := LocalCandidateForUID(1001, now); ok || err != nil {
		t.Fatalf("passwd line without files: ok=%t err=%v; want no candidate", ok, err)
	}

	// Two names in /etc/passwd at one uid: a shared uid, known without
	// asking a directory.
	write(nsswitchPath, "passwd: files sss\ngroup: files sss\n")
	write(localPasswdPath, entry+"opsclone:x:1001:1001::/home/opsclone:/bin/bash\n")
	var shared *SharedUIDError
	if _, _, ok, err := LocalCandidateForUID(1001, now); ok || !errors.As(err, &shared) || len(shared.Accounts) != 2 {
		t.Fatalf("two /etc/passwd names: ok=%t err=%v; want a SharedUIDError naming both", ok, err)
	}
}

// Two /etc/passwd names at one uid while SSSD is stopped: a SharedUIDError,
// not a plain failure the gateway would answer with the default.
func TestASharedUIDIsProvedWhileSSSDIsStopped(t *testing.T) {
	write := r2Fixtures(t)
	entry := r2Entry
	now := time.Now()
	write(nsswitchPath, "passwd: files sss\ngroup: files sss\n")
	write(localPasswdPath, entry+"opsclone:x:1001:1001::/home/opsclone:/bin/bash\n")
	var shared *SharedUIDError
	results := map[string]commandResult{
		"passwd 1001":          {stdout: []byte(entry)},
		"-s files passwd 1001": {stdout: []byte(entry)},
	}
	var candidate *UnprovenFactsError
	_, err := newFakeNSS(&fakeRun{results: results}).DirectoryFactsForUID(1001, now)
	if !errors.As(err, &shared) || errors.As(err, &candidate) {
		t.Fatalf("shared uid, SSSD stopped: err = %v; want a SharedUIDError without a candidate", err)
	}

	// Control: one account, SSSD stopped, is still unproven with a candidate.
	write(localPasswdPath, entry)
	if _, err := newFakeNSS(&fakeRun{results: results}).DirectoryFactsForUID(1001, now); !errors.As(err, &candidate) || errors.As(err, &shared) {
		t.Fatalf("one account, SSSD stopped: err = %v; want an UnprovenFactsError", err)
	}
}
