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

// A pending cleanup for one connector keeps a removed account's state while
// another connector's manifest row is removed. An unrelated enrolled account
// still gets its purge.
func TestRemoveAllPurgeKeepsStateForAPendingCleanupWithAKeptHome(t *testing.T) {
	keptUID, otherUID, gid := os.Getuid()+1, os.Getuid()+2, os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"sample-kept": {Name: "sample-kept", UID: keptUID, GID: gid, Home: "/var/empty"},
	}}
	f := newStandaloneFixture(t, resolver)
	keptHome := f.home(t, "sample-kept", 0o700)
	otherHome := f.home(t, "sample-enrolled", 0o700)
	enterpriseHookCheckHome = func(home string, uid int) enterprisehooks.HomeCheck {
		if (home == keptHome && uid == keptUID) || (home == otherHome && uid == otherUID) {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeUntrusted}
	}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-kept", UID: &keptUID, GID: &gid, UserHome: keptHome},
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-enrolled", UID: &otherUID, GID: &gid, UserHome: otherHome},
	)
	manifest, err := enterprisehooks.LoadManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	rows := resolveEnterpriseHookRemoveRows(manifest)
	jobs, pendingRows, failedRows := enterpriseHookRemoveJobs(rows)
	if len(pendingRows) != 0 || len(failedRows) != 0 || !enterpriseHookJobRemoves(jobs[keptUID], "codex") || !enterpriseHookJobRemoves(jobs[otherUID], "codex") {
		t.Fatalf("manifest removal jobs: pending=%v failed=%v jobs=%+v", pendingRows, failedRows, jobs)
	}
	if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{{
		Connector: "hermes", UID: keptUID, User: "sample-kept", UserHome: keptHome, RecordedAt: "2026-10-14T00:00:00Z",
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{}
	failed := runEnterpriseHookPendingCleanups(cmd, &report, jobs)
	if len(report.Pending) != 1 || !strings.HasPrefix(report.Pending[0], "sample-kept/hermes: ") || len(report.Failed) != 0 || !failed[keptUID] || failed[otherUID] {
		t.Fatalf("pending cleanup must protect the kept home without failing uninstall: %+v, %v", report, failed)
	}
	notPurged := addEnterpriseHookStatePurges(jobs, rows, failed)
	if len(notPurged) != 1 || !strings.HasPrefix(notPurged[0], "sample-kept: ") {
		t.Fatalf("purge must name the account whose state stays: %v", notPurged)
	}
	for _, target := range jobs[keptUID].Request.Targets {
		if target.Mode == enterpriseHookWorkerModePurge {
			t.Fatalf("purge scheduled for account with a pending cleanup: %+v", target)
		}
	}
	purges := 0
	for _, target := range jobs[otherUID].Request.Targets {
		if target.Mode == enterpriseHookWorkerModePurge && target.Options.DataDir == filepath.Join(otherHome, ".defenseclaw") {
			purges++
		}
	}
	if purges != 1 {
		t.Fatalf("unrelated enrolled account got %d purges, want one: %+v", purges, jobs[otherUID].Request.Targets)
	}
}
