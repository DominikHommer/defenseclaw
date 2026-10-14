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

// homeGoneFixture records two pending Hermes cleanups of accounts whose
// directory home is now /var/empty-like (a removed macOS AD mobile account):
// gone's recorded home no longer exists; kept's recorded home still does.
func homeGoneFixture(t *testing.T) (f *standaloneFixture, resolver standaloneTestResolver, gone, kept string) {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	resolver = standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f = newStandaloneFixture(t, resolver)
	empty := filepath.Join(f.root, "var-empty")
	gone = filepath.Join(f.homes, "dcad-gone") // removed with the mobile account
	kept = f.home(t, "dcad-kept", 0o700)
	resolver.accounts["dcad-gone"] = unixidentity.Account{Name: "dcad-gone", UID: uid, GID: gid, Home: empty}
	resolver.accounts["dcad-kept"] = unixidentity.Account{Name: "dcad-kept", UID: uid + 1, GID: gid, Home: empty}
	f.writeManifest(t)
	if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{
		{Connector: "hermes", UID: uid, User: "dcad-gone", UserHome: gone, RecordedAt: "2026-10-14T00:00:00Z"},
		{Connector: "hermes", UID: uid + 1, User: "dcad-kept", UserHome: kept, RecordedAt: "2026-10-14T00:00:00Z"},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return f, resolver, gone, kept
}

// GAP-0543: the guardian retried forever the cleanup of a removed macOS AD
// mobile account, whose recorded home is gone and whose directory home is
// now /var/empty. It retires such a cleanup as "home gone"; a cleanup whose
// recorded home still exists keeps failing, as nothing proves its
// registration went.
func TestStandaloneCleanupRetiresATargetWhoseHomeIsGone(t *testing.T) {
	f, resolver, _, kept := homeGoneFixture(t)
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
	if len(pending) != 1 || pending[0].User != "dcad-kept" || pending[0].UserHome != kept ||
		!strings.Contains(pending[0].LastError, "no longer matches the directory home") {
		t.Fatalf("only the cleanup whose recorded home still exists may stay, with its error: %+v", pending)
	}
	if !strings.Contains(log.String(), "hermes/dcad-gone: home gone") {
		t.Fatalf("the guardian does not say why it retired the cleanup: %s", log.String())
	}
	if len(f.workerTargets()) != 0 {
		t.Fatalf("no worker may run in a home that is gone or mismatched: %+v", f.workerTargets())
	}
}

// GAP-0553: a managed uninstall stopped with per_user_hooks_remaining for
// removed AD mobile accounts whose pending guardian cleanups named homes
// that are gone. remove-all reports them as pending (the uninstall warns
// and goes on); a mismatched home that still exists stays a failure.
func TestRemoveAllReportsAPendingCleanupWhoseHomeIsGoneAsPending(t *testing.T) {
	homeGoneFixture(t)
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{}
	failed := runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
	if len(report.Pending) != 1 || report.Pending[0] != "dcad-gone/hermes" || report.Removed != 0 {
		t.Fatalf("the cleanup in a home that is gone must be reported pending, not removed: %+v", report)
	}
	if len(report.Failed) != 1 || !strings.HasPrefix(report.Failed[0], "dcad-kept/hermes: ") || !failed[os.Getuid()+1] || failed[os.Getuid()] {
		t.Fatalf("the cleanup whose recorded home exists must still fail: %+v, %v", report, failed)
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
