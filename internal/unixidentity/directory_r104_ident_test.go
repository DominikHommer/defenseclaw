//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// sameNameHost points the realm sources and nsswitch.conf at test files.
func sameNameHost(t *testing.T, realms func(context.Context) ([]Realm, error), krb5, nss string) {
	t.Helper()
	dir := t.TempDir()
	oldRealms, oldListed, oldKrb5, oldSSSD, oldSSSDDir, oldNSS := hostRealms, lastListedRealms, krb5ConfPath, sssdConfPath, sssdConfDir, nsswitchPath
	t.Cleanup(func() {
		hostRealms, lastListedRealms, krb5ConfPath, sssdConfPath, sssdConfDir, nsswitchPath = oldRealms, oldListed, oldKrb5, oldSSSD, oldSSSDDir, oldNSS
	})
	hostRealms, lastListedRealms = realms, func() []Realm { return nil }
	krb5ConfPath, sssdConfPath, nsswitchPath = filepath.Join(dir, "krb5.conf"), filepath.Join(dir, "sssd.conf"), filepath.Join(dir, "nsswitch.conf")
	sssdConfDir = filepath.Join(dir, "conf.d")
	if krb5 != "" {
		if err := os.WriteFile(krb5ConfPath, []byte(krb5), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(nsswitchPath, []byte(nss), 0o644); err != nil {
		t.Fatal(err)
	}
}

// GAP-1131, GAP-1132: with realmd failing or answering no realm, the
// directory twin of a local account is still found through the joined
// domain krb5.conf names, and with no source at all a bare name is refused
// rather than taken for the local account.
func TestSameNameAccountsWithoutRealmd(t *testing.T) {
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{
		"passwd alice":              {stdout: []byte("alice:x:1001:1001::/home/alice:/bin/bash\n")},
		"passwd alice@corp.example": {stdout: []byte("alice@corp.example:*:2001:2001::/home/alice@corp.example:/bin/bash\n")},
	}})
	local := Account{Name: "alice", UID: 1001}
	krb5 := "[libdefaults]\n  default_realm = CORP.EXAMPLE\n"
	for name, realms := range map[string]func(context.Context) ([]Realm, error){
		"realmd fails":          func(context.Context) ([]Realm, error) { return nil, errors.New("realmd timed out") },
		"realmd lists no realm": func(context.Context) ([]Realm, error) { return nil, nil },
	} {
		t.Run(name, func(t *testing.T) {
			sameNameHost(t, realms, krb5, "passwd: files sss\n")
			twins, err := SameNameAccounts(context.Background(), r, local)
			if err != nil || len(twins) != 1 || twins[0].UID != 2001 {
				t.Fatalf("twins = %+v, %v; want the directory alice", twins, err)
			}
		})
	}
	t.Run("nothing names the domains", func(t *testing.T) {
		sameNameHost(t, func(context.Context) ([]Realm, error) { return nil, errors.New("realmd timed out") }, "", "passwd: files sss\n")
		writeTestFile(t, sssdConfPath, "[sssd]\nservices = nss, pam\n")
		twins, err := SameNameAccounts(context.Background(), r, local)
		var unknown *useridentity.NamesakesUnknownError
		if len(twins) != 0 || !errors.As(err, &unknown) || !strings.Contains(err.Error(), "qualified name") {
			t.Fatalf("twins = %+v, %v; want the bare name refused", twins, err)
		}
	})
	t.Run("a files-only host", func(t *testing.T) {
		sameNameHost(t, func(context.Context) ([]Realm, error) { return nil, errors.New("no system bus") }, "", "passwd: files\n")
		if twins, err := SameNameAccounts(context.Background(), r, local); err != nil || len(twins) != 0 {
			t.Fatalf("twins = %+v, %v; a host with no directory has none", twins, err)
		}
	})
}

// GAP-1123: passwd: compat with passwd_compat: names the services compat
// reads in place of the local file, so a directory account included with a
// "+" line is not taken for a local one.
func TestNSSCompatListsItsServices(t *testing.T) {
	content := "passwd: compat\npasswd_compat: ldap\ngroup: compat\ninitgroups: compat\n"
	if got := ParseNSSwitchServices(content, "passwd"); !reflect.DeepEqual(got, []string{"files", "ldap"}) {
		t.Fatalf("passwd services = %v", got)
	}
	if got := ParseNSSwitchServices(content, "group"); !reflect.DeepEqual(got, []string{"files", "nis"}) {
		t.Fatalf("group services = %v, want compat's default nis", got)
	}
	if got := ParseNSSwitchServices(content, "initgroups"); !reflect.DeepEqual(got, []string{"compat"}) {
		t.Fatalf("initgroups services = %v", got)
	}
	oldPasswd, oldNSS := localPasswdPath, nsswitchPath
	t.Cleanup(func() { localPasswdPath, nsswitchPath = oldPasswd, oldNSS })
	dir := t.TempDir()
	localPasswdPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "nsswitch.conf")
	// compat asks passwd_compat for the + lines of /etc/passwd.
	for path, data := range map[string]string{localPasswdPath: "root:x:0:0::/root:/bin/sh\n+::::::\n", nsswitchPath: content} {
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	line := []byte("bob:*:80001:80001::/home/bob:/bin/bash\n")
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{
		"passwd 80001": {stdout: line}, "-s ldap passwd 80001": {stdout: line},
	}})
	facts, err := r.DirectoryFactsWithoutGroupsForUID(80001, time.Now())
	if err != nil || facts.Directory != useridentity.DirectoryLDAP || facts.Source != useridentity.SourceNSSLDAP {
		t.Fatalf("facts of a compat-included LDAP account = %+v, %v", facts, err)
	}
}

// GAP-0550: a local account no directory account shares a name with keeps
// the groups an RFC 2307 directory lists it in, and the directory's name of
// its primary gid.
func TestLocalAccountKeepsMemberListDirectoryGroups(t *testing.T) {
	// An nslcd that completes every search (nslcdSearchesComplete).
	startFakeNSLCD(t, &fakeNSLCD{})
	oldPasswd, oldGroup, oldNSS := localPasswdPath, localGroupPath, nsswitchPath
	t.Cleanup(func() { localPasswdPath, localGroupPath, nsswitchPath = oldPasswd, oldGroup, oldNSS })
	dir := t.TempDir()
	localPasswdPath, localGroupPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), filepath.Join(dir, "nsswitch.conf")
	for path, content := range map[string]string{
		localPasswdPath: "alice:x:1001:5100::/home/alice:/bin/sh\n",
		localGroupPath:  "local-team:x:7000:alice\n",
		nsswitchPath:    "passwd: files ldap\ninitgroups: files ldap\ngroup: files ldap\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	localLine := []byte("alice:x:1001:5100::/home/alice:/bin/sh\n")
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{
		"passwd 1001":              {stdout: localLine},
		"passwd alice":             {stdout: localLine},
		"-s ldap initgroups alice": {stdout: []byte("alice 5100 5200\n")},
		"group 5100 5200":          {stdout: []byte("staff:x:5100:\nengineering:x:5200:alice\n")},
	}})
	ids, err := r.GroupIDs(Account{Name: "alice", UID: 1001, GID: 5100})
	if err != nil || !reflect.DeepEqual(ids, []int{5100, 5200, 7000}) {
		t.Fatalf("group ids = %v, %v", ids, err)
	}
	facts, err := r.DirectoryFactsForUID(1001, time.Now())
	if err != nil || facts.Directory != useridentity.DirectoryLocal || !reflect.DeepEqual(facts.Groups, []string{"staff", "engineering", "local-team"}) {
		t.Fatalf("facts = %+v, %v", facts, err)
	}
}

// GAP-1247: the lookup budget names the largest supported membership one
// cold SSSD answer at a time; the old fixed budget ran out at about 700.
func TestDirectoryLookupBudgetNamesAColdLargeMembership(t *testing.T) {
	oldCold, oldBase := coldGroupLookup, directoryLookupBase
	t.Cleanup(func() { coldGroupLookup, directoryLookupBase = oldCold, oldBase })
	coldGroupLookup, directoryLookupBase = time.Millisecond, 100*time.Millisecond
	slow := func(ctx context.Context, _ string, args []string, _ ...outputFilter) (commandResult, error) {
		select {
		case <-time.After(time.Duration(len(args)-1) * coldGroupLookup):
		case <-ctx.Done():
			return commandResult{}, ctx.Err()
		}
		return commandResult{exitCode: getentExitNotFound}, nil
	}
	ids := make([]int, 700)
	for i := range ids {
		ids[i] = 100000 + i
	}
	run := func(budget time.Duration) error {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		_, err := (&NSSResolver{path: "/usr/bin/getent", runner: slow, ctx: ctx}).groupNames(ids)
		return err
	}
	if err := run(DirectoryLookupBudget()); err != nil {
		t.Fatalf("700 cold groups within the budget: %v", err)
	}
	if err := run(directoryLookupBase); err == nil {
		t.Fatal("the fixed base budget named 700 cold groups; the control does not reproduce the timeout")
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Review of GAP-1131: realmd answering an empty list without an error, with
// no realm file to stand in, refuses a bare name while an SSSD configuration
// may serve a domain DefenseClaw cannot name (sssd.conf it cannot read, a
// conf.d snippet, winbind); a host with the sss module and no SSSD
// configuration (the RHEL default) keeps the bare name.
func TestSameNameAccountsEmptyRealmdAnswer(t *testing.T) {
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{
		"passwd alice": {stdout: []byte("alice:x:1001:1001::/home/alice:/bin/bash\n")},
	}})
	local := Account{Name: "alice", UID: 1001}
	empty := func(context.Context) ([]Realm, error) { return nil, nil }
	for name, setup := range map[string]func(t *testing.T){
		"sssd.conf names no readable domain": func(t *testing.T) { writeTestFile(t, sssdConfPath, "[sssd]\nservices = nss\n") },
		"a conf.d snippet": func(t *testing.T) {
			writeTestFile(t, filepath.Join(sssdConfDir, "corp.conf"), "[domain/corp.example]\n")
		},
	} {
		t.Run(name, func(t *testing.T) {
			sameNameHost(t, empty, "", "passwd: files sss\n")
			setup(t)
			twins, err := SameNameAccounts(context.Background(), r, local)
			var unknown *useridentity.NamesakesUnknownError
			if len(twins) != 0 || !errors.As(err, &unknown) {
				t.Fatalf("twins = %+v, %v; want the bare name refused", twins, err)
			}
		})
	}
	t.Run("winbind", func(t *testing.T) {
		sameNameHost(t, empty, "", "passwd: files winbind\n")
		previousSamba, previousTrusts := sambaConfPath, winbindTrustedDomains
		t.Cleanup(func() { sambaConfPath, winbindTrustedDomains = previousSamba, previousTrusts })
		sambaConfPath = filepath.Join(t.TempDir(), "smb.conf")
		writeTestFile(t, sambaConfPath, "[global]\nworkgroup = CORP\n")
		winbindTrustedDomains = func(context.Context) ([]string, error) { return nil, errors.New("winbindd is not running") }
		var unknown *useridentity.NamesakesUnknownError
		if twins, err := SameNameAccounts(context.Background(), r, local); len(twins) != 0 || !errors.As(err, &unknown) {
			t.Fatalf("twins = %+v, %v; want the bare name refused", twins, err)
		}
	})
	t.Run("sss without an SSSD configuration", func(t *testing.T) {
		for _, realms := range []func(context.Context) ([]Realm, error){empty, func(context.Context) ([]Realm, error) { return nil, errors.New("realm: command not found") }} {
			sameNameHost(t, realms, "", "passwd: sss files systemd\n")
			if twins, err := SameNameAccounts(context.Background(), r, local); err != nil || len(twins) != 0 {
				t.Fatalf("twins = %+v, %v; a host with no SSSD configuration serves no domain", twins, err)
			}
		}
	})
}

// Review of GAP-1131: a qualified candidate lookup that fails, rather than
// finding nothing, leaves the twin it would have found unknown.
func TestSameNameAccountsKeepsCandidateLookupErrors(t *testing.T) {
	r := newFakeNSS(&fakeRun{
		results: map[string]commandResult{"passwd alice": {stdout: []byte("alice:x:1001:1001::/home/alice:/bin/bash\n")}},
		errs:    map[string]error{"passwd alice@corp.example": errors.New("sssd timed out")},
	})
	sameNameHost(t, func(context.Context) ([]Realm, error) {
		return []Realm{{Name: "CORP.EXAMPLE", Domain: "corp.example"}}, nil
	}, "", "passwd: files sss\n")
	twins, err := SameNameAccounts(context.Background(), r, Account{Name: "alice", UID: 1001})
	var unknown *useridentity.NamesakesUnknownError
	if len(twins) != 0 || !errors.As(err, &unknown) || !strings.Contains(err.Error(), "sssd timed out") {
		t.Fatalf("twins = %+v, %v; want the bare name refused with the lookup error", twins, err)
	}
}

// Review of GAP-0550: a member-list directory that does not answer for a
// local account fails its groups instead of dropping the groups it lists,
// so a strict-profile LDAP group is never lost to an outage (fail closed).
func TestLocalAccountGroupsFailWhenTheDirectoryDoesNotAnswer(t *testing.T) {
	// An nslcd that completes every search (nslcdSearchesComplete).
	startFakeNSLCD(t, &fakeNSLCD{})
	oldPasswd, oldGroup, oldNSS := localPasswdPath, localGroupPath, nsswitchPath
	t.Cleanup(func() { localPasswdPath, localGroupPath, nsswitchPath = oldPasswd, oldGroup, oldNSS })
	dir := t.TempDir()
	localPasswdPath, localGroupPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), filepath.Join(dir, "nsswitch.conf")
	writeTestFile(t, localPasswdPath, "alice:x:1001:5100::/home/alice:/bin/sh\n")
	writeTestFile(t, localGroupPath, "local-team:x:7000:alice\n")
	writeTestFile(t, nsswitchPath, "passwd: files ldap\ninitgroups: files ldap\ngroup: files ldap\n")
	localLine := []byte("alice:x:1001:5100::/home/alice:/bin/sh\n")
	base := map[string]commandResult{
		"passwd 1001":              {stdout: localLine},
		"passwd alice":             {stdout: localLine},
		"-s ldap initgroups alice": {stdout: []byte("alice 5100 5200\n")},
		"group 5100 5200":          {stdout: []byte("staff:x:5100:\nstrict-ai:x:5200:alice\n")},
	}
	for name, failing := range map[string]string{
		"account lookup times out": "-s ldap passwd alice",
		"member lookup times out":  "-s ldap initgroups alice",
		"group naming times out":   "group 5100 5200",
	} {
		t.Run(name, func(t *testing.T) {
			r := newFakeNSS(&fakeRun{results: base, errs: map[string]error{failing: context.DeadlineExceeded}})
			if ids, err := r.GroupIDs(Account{Name: "alice", UID: 1001, GID: 5100}); err == nil {
				t.Fatalf("group ids = %v without an error while the directory does not answer", ids)
			}
			if facts, err := r.DirectoryFactsForUID(1001, time.Now()); err == nil {
				t.Fatalf("facts = %+v without an error while the directory does not answer", facts)
			}
		})
	}
	t.Run("a directory that holds no such member", func(t *testing.T) {
		quiet := map[string]commandResult{
			"passwd 1001": {stdout: localLine}, "passwd alice": {stdout: localLine},
			"-s ldap initgroups alice": {stdout: []byte("alice\n")}, "-s ldap group": {stdout: []byte("ldap-users:*:9000:\n")},
		}
		r := newFakeNSS(&fakeRun{results: quiet})
		facts, err := r.DirectoryFactsForUID(1001, time.Now())
		if err != nil || !reflect.DeepEqual(facts.Groups, []string{"5100", "local-team"}) {
			t.Fatalf("facts = %+v, %v; a definitive not-found keeps the local groups", facts, err)
		}
	})
}
