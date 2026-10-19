//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// GAP-0191: while SSSD cannot reach the directory it answers from its cache,
// and for an account whose memberships it never looked up the answer is the
// primary group alone. The facts say so (OnlyPrimaryGroup), also for an
// account with a private group, whose directory primary group (Domain Users)
// SSSD lists besides it; the /etc/group groups that list the account do not
// count. An account SSSD lists in another domain group is not marked.
func TestSSSDAccountListedInItsPrimaryGroupOnly(t *testing.T) {
	origNSS, origRealms, origPasswd, origGroup := nsswitchPath, hostRealms, localPasswdPath, localGroupPath
	t.Cleanup(func() {
		nsswitchPath, hostRealms, localPasswdPath, localGroupPath = origNSS, origRealms, origPasswd, origGroup
	})
	dir := t.TempDir()
	nsswitchPath, localPasswdPath, localGroupPath = filepath.Join(dir, "nsswitch.conf"), filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	for path, content := range map[string]string{nsswitchPath: "passwd: files sss\n", localPasswdPath: "", localGroupPath: "docker:x:7000:alice\n"} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	hostRealms = func(context.Context) ([]Realm, error) {
		return []Realm{{Domain: "corp.example.com", Name: "CORP.EXAMPLE.COM", ServerSoftware: "active-directory", ClientSoftware: "sssd"}}, nil
	}
	const corp = "S-1-5-21-1-2-3"
	startFakeSSSD(t, map[string]string{
		"uid:80001": corp + "-1101", `name:corp.example.com\alice`: corp + "-1101", "sid:" + corp + "-1101": "80001",
		`name:CORP\alice`: corp + "-1101", "gid:5000": corp + "-513", "gid:5300": corp + "-1201",
	})
	names := map[int]string{5000: "domain users", 5300: "devs", 7000: "docker", 80001: "alice"}
	for _, tc := range []struct {
		gid    int
		groups []int
		want   bool
	}{
		{5000, []int{5000}, true},
		{5000, []int{5000, 5300}, false},
		{80001, []int{80001, 5000}, true},
		{80001, []int{80001, 5000, 5300}, false},
		{80001, []int{80001, 5300}, false},
	} {
		account := commandResult{stdout: []byte("alice:*:80001:" + strconv.Itoa(tc.gid) + "::/home/alice:/bin/bash\n")}
		initgroups := `corp.example.com\alice`
		ids := map[int]bool{tc.gid: true, 7000: true}
		for _, id := range tc.groups {
			initgroups += " " + strconv.Itoa(id)
			ids[id] = true
		}
		query, answer := "group", ""
		for _, id := range []int{5000, 5300, 7000, 80001} {
			if ids[id] {
				query += " " + strconv.Itoa(id)
				answer += names[id] + ":*:" + strconv.Itoa(id) + ":\n"
			}
		}
		f := &fakeRun{results: map[string]commandResult{
			"passwd 80001": account, "-s sss passwd 80001": account,
			`initgroups corp.example.com\alice`: {stdout: []byte(initgroups + "\n")},
			query:                               {stdout: []byte(answer)},
		}}
		facts, err := newFakeNSS(f).DirectoryFactsForUID(80001, time.Now())
		if err != nil || facts.OnlyPrimaryGroup != tc.want {
			t.Errorf("gid %d, groups %v: OnlyPrimaryGroup = %t (groups %q), err %v; want %t", tc.gid, tc.groups, facts.OnlyPrimaryGroup,
				facts.Groups, err, tc.want)
		}
	}
}
