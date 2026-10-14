//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func longRehomeReportTestPath(name string) string {
	return filepath.Join("/tmp", strings.Repeat("a", 55), strings.Repeat("b", 55),
		strings.Repeat("c", 55), strings.Repeat("d", 55), strings.Repeat(name, 8))
}

func TestRemoveAllRehomeReportKeepsTheFullRemedyWithLongHomes(t *testing.T) {
	const remedy = "fix the account's home to an existing account-owned directory without symlinks or group/other write, or remove the account, then rerun"
	for _, test := range []struct {
		name, oldHome, currentHome string
	}{
		{name: "long", oldHome: longRehomeReportTestPath("old"), currentHome: longRehomeReportTestPath("new")},
		{name: "short", oldHome: "/tmp/sample-old", currentHome: "/tmp/sample-current"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			uid, gid := 31415, 31415
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: test.currentHome}
			entry := enterpriseHookUserCleanup{Connector: "opencode", User: "sample-user", UID: uid,
				UserHome: test.oldHome, DataDir: filepath.Join(test.oldHome, ".defenseclaw")}
			if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{entry}, time.Now()); err != nil {
				t.Fatal(err)
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			report := enterpriseHooksRemoveAllReport{}
			skip := runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
			if report.Removed != 0 || len(report.Failed) != 1 || skip[uid] != enterpriseHookPurgeSkipFailed {
				t.Fatalf("report = %+v, skip = %+v", report, skip)
			}
			got := report.Failed[0]
			if test.name == "long" {
				if len(test.oldHome) < 240 || len(test.currentHome) < 240 {
					t.Fatalf("home paths are not long enough: %d and %d", len(test.oldHome), len(test.currentHome))
				}
				if !strings.Contains(got, remedy) || !strings.Contains(got, "/.../") ||
					strings.Contains(got, test.oldHome) || strings.Contains(got, test.currentHome) || len(got) >= 800 {
					t.Fatalf("long-home report lost remedy or bound: %d bytes, %q", len(got), got)
				}
				return
			}
			_, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &strings.Builder{}, entry, resolver)
			if err == nil {
				t.Fatal("short-home fixture did not fail")
			}
			want := "sample-user/opencode: " + boundedEnterpriseHookUserCleanupText(err.Error())
			if got != want {
				t.Fatalf("short-home report = %q, want byte-identical %q", got, want)
			}
		})
	}
}
