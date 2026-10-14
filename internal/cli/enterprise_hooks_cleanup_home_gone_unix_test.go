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

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// homeGoneFixture records three pending Hermes cleanups. dcad-gone and
// dcad-kept are removed macOS AD mobile accounts, whose directory home is
// now /var/empty: gone's recorded home no longer exists, kept's folder was
// kept (sysadminctl -deleteUser -keepHome). dcad-moved is a live account
// the directory re-homed to a real path while its recorded home is still
// there.
func homeGoneFixture(t *testing.T) (f *standaloneFixture, resolver standaloneTestResolver, gone, kept, moved string) {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	resolver = standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f = newStandaloneFixture(t, resolver)
	gone = filepath.Join(f.homes, "dcad-gone") // removed with the mobile account
	kept = f.home(t, "dcad-kept", 0o700)
	moved = f.home(t, "dcad-moved", 0o700)
	resolver.accounts["dcad-gone"] = unixidentity.Account{Name: "dcad-gone", UID: uid, GID: gid, Home: "/var/empty"}
	resolver.accounts["dcad-kept"] = unixidentity.Account{Name: "dcad-kept", UID: uid + 1, GID: gid, Home: "/var/empty"}
	resolver.accounts["dcad-moved"] = unixidentity.Account{Name: "dcad-moved", UID: uid + 2, GID: gid, Home: filepath.Join(f.homes, "dcad-moved-new")}
	f.writeManifest(t)
	if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{
		{Connector: "hermes", UID: uid, User: "dcad-gone", UserHome: gone, RecordedAt: "2026-10-14T00:00:00Z"},
		{Connector: "hermes", UID: uid + 1, User: "dcad-kept", UserHome: kept, RecordedAt: "2026-10-14T00:00:00Z"},
		{Connector: "hermes", UID: uid + 2, User: "dcad-moved", UserHome: moved, RecordedAt: "2026-10-14T00:00:00Z"},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return f, resolver, gone, kept, moved
}

// GAP-0543: the guardian retried forever the cleanup of a removed macOS AD
// mobile account, whose recorded home is gone and whose directory home is
// now /var/empty. It retires such a cleanup as "home gone", without also
// saying the cleanup was done (Codex F8); a cleanup whose recorded home
// still exists keeps failing, as nothing proves its registration went.
func TestStandaloneCleanupRetiresATargetWhoseHomeIsGone(t *testing.T) {
	f, resolver, _, kept, moved := homeGoneFixture(t)
	var log bytes.Buffer
	manifest, err := enterprisehooks.LoadManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &log, manifest,
		enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, resolver, time.Now()); err != nil {
		t.Fatal(err)
	}
	pending, err := loadEnterpriseHookUserCleanups(f.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 || pending[0].User != "dcad-kept" || pending[0].UserHome != kept ||
		!strings.Contains(pending[0].LastError, "no longer matches the directory home /var/empty, which is no home") ||
		pending[1].User != "dcad-moved" || pending[1].UserHome != moved ||
		!strings.Contains(pending[1].LastError, "no longer matches the directory home") || strings.Contains(pending[1].LastError, "no home") {
		t.Fatalf("only the cleanups whose recorded home still exists may stay, each with its error: %+v", pending)
	}
	if !strings.Contains(log.String(), "hermes/dcad-gone: home gone") {
		t.Fatalf("the guardian does not say why it retired the cleanup: %s", log.String())
	}
	if strings.Contains(log.String(), "hermes/dcad-gone: no longer enrolled; per-user cleanup done") {
		t.Fatalf("a cleanup retired as home gone removed nothing, so it may not be logged done: %s", log.String())
	}
	if !strings.Contains(log.String(), "warn: per-user cleanup of hermes/dcad-kept: ") {
		t.Fatalf("the guardian does not warn for the kept home it keeps retrying: %s", log.String())
	}
	if len(f.workerTargets()) != 0 {
		t.Fatalf("no worker may run in a home that is gone or mismatched: %+v", f.workerTargets())
	}
}

// GAP-0553: a managed uninstall stopped with per_user_hooks_remaining for
// removed AD mobile accounts with pending guardian cleanups. remove-all
// reports them as pending, each with a reason that names the recorded home
// (the uninstall warns and goes on): a home that is gone, and a kept home
// of an account the directory now gives /var/empty. A live account
// re-homed to a real path stays a failure.
func TestRemoveAllReportsAPendingCleanupWhoseHomeIsGoneAsPending(t *testing.T) {
	_, _, gone, kept, _ := homeGoneFixture(t)
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{}
	failed := runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
	if len(report.Pending) != 2 || report.Removed != 0 ||
		!strings.HasPrefix(report.Pending[0], "dcad-gone/hermes: its recorded home "+gone+" is gone") ||
		!strings.HasPrefix(report.Pending[1], "dcad-kept/hermes: the directory gives the account no home (/var/empty)") ||
		!strings.Contains(report.Pending[1], "remove them from the hermes config in "+kept) {
		t.Fatalf("the cleanups of removed accounts must be reported pending with their recorded home, not removed: %+v", report)
	}
	for _, entry := range report.Pending {
		if strings.Contains(entry, "once it is") {
			t.Fatalf("a removed account's home will not become available: %q", entry)
		}
	}
	if len(report.Failed) != 1 || !strings.HasPrefix(report.Failed[0], "dcad-moved/hermes: ") ||
		!failed[os.Getuid()+2] || !failed[os.Getuid()+1] || failed[os.Getuid()] {
		t.Fatalf("only the re-homed live account may still fail: %+v, %v", report, failed)
	}
}

// The directory homes a removed or disabled account answers with are no
// home; a real path is one.
func TestEnterpriseHookDirectoryNoHome(t *testing.T) {
	for home, want := range map[string]bool{
		"/var/empty":   true,
		"/var/empty/":  true,
		"/dev/null":    true,
		"/nonexistent": true,
		"var/empty":    true,
		" ":            true,
		"/Users/dcad":  false,
		"/home/dcad":   false,
		"/var/root":    false,
	} {
		if got := enterpriseHookDirectoryNoHome(home); got != want {
			t.Errorf("enterpriseHookDirectoryNoHome(%q) = %v, want %v", home, got, want)
		}
	}
}

// A recorded home is gone only when its parent answers and the home is not
// there: a missing parent (an unmounted volume) or a home that exists is not.
func TestEnterpriseHookRecordedHomeGone(t *testing.T) {
	root := t.TempDir()
	present := filepath.Join(root, "present")
	if err := os.Mkdir(present, 0o700); err != nil {
		t.Fatal(err)
	}
	for home, want := range map[string]bool{
		filepath.Join(root, "missing"): true,
		present:                        false,
		filepath.Join(root, "unmounted", "missing"): false,
		"relative/home": false,
		"/":             false,
	} {
		if got := enterpriseHookRecordedHomeGone(home); got != want {
			t.Errorf("enterpriseHookRecordedHomeGone(%q) = %v, want %v", home, got, want)
		}
	}
}
