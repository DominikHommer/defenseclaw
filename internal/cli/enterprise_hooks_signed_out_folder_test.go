// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// #1105, GAP-0211: the 1.0.2 -> 1.0.3 upgrade with a signed-out account
// whose hooks folder had one extra permission entry returned 1603 twice.
// Only that exact failure of the account's own DefenseClaw folder or hooks
// folder, while it is signed out, waits for the next sign-in; everything
// else stays a failure.
func TestEnterpriseHookSignedOutUntrustedFolder(t *testing.T) {
	const (
		dataDir   = `C:\Users\r103gb13-u1\.defenseclaw`
		unavail   = "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable (verification: "
		hookCheck = "enterprise hooks: managed hook directory verification failed: "
		dataCheck = "enterprise hooks: managed data directory verification failed: "
	)
	// The error the live T2 cell recorded (TST-2076).
	live := unavail + hookCheck + `enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks has 8 ACEs, expected 7)`
	for _, tc := range []struct {
		name   string
		row    enterpriseHookReconcileRow
		folder string
	}{
		{name: "live hooks folder", row: enterpriseHookReconcileRow{Error: live}, folder: dataDir + `\hooks`},
		{name: "case and trailing separator", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: managed Windows DACL is not protected on c:\users\R103GB13-U1\.defenseclaw\hooks\)`}, folder: dataDir + `\hooks`},
		{name: "data folder owner", row: enterpriseHookReconcileRow{Error: unavail + dataCheck +
			`enterprise hooks: owner SID S-1-5-32-545 does not match target SID S-1-5-21-1-2-3-1123 on C:\Users\r103gb13-u1\.defenseclaw)`}, folder: dataDir},
		{name: "unexpected entry", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks contains unexpected or duplicate ACE for principal S-1-5-11 (mask 0x1301bf, inheritance 0x3))`}, folder: dataDir + `\hooks`},
		{name: "non-canonical entry", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks contains non-canonical ACE type at index 2)`}, folder: dataDir + `\hooks`},
		{name: "unreadable DACL", row: enterpriseHookReconcileRow{Error: unavail + dataCheck +
			`enterprise hooks: null or unreadable Windows DACL on C:\Users\r103gb13-u1\.defenseclaw)`}, folder: dataDir},

		{name: "connected account", row: enterpriseHookReconcileRow{Error: hookCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks has 8 ACEs, expected 7`}},
		{name: "another account's folder", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\other\.defenseclaw\hooks has 8 ACEs, expected 7)`}},
		{name: "hook check naming the data folder", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw has 8 ACEs, expected 7)`}},
		{name: "a folder below hooks", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks\x has 8 ACEs, expected 7)`}},
		{name: "junction", row: enterpriseHookReconcileRow{Error: unavail + hookCheck +
			`enterprise hooks: symlinks, junctions, and reparse points are not allowed: C:\Users\r103gb13-u1\.defenseclaw\hooks)`}},
		{name: "runtime file", row: enterpriseHookReconcileRow{Error: unavail +
			`enterprise hooks: required managed runtime verification failed for C:\Users\r103gb13-u1\.defenseclaw\hooks\.hookcfg: ` +
			`enterprise hooks: managed Windows DACL on C:\Users\r103gb13-u1\.defenseclaw\hooks\.hookcfg has 8 ACEs, expected 7)`}},
		{name: "token mismatch", row: enterpriseHookReconcileRow{Error: unavail + "enterprise hooks: per-user connector-scoped token does not match)"}},
		{name: "text after the folder failure", row: enterpriseHookReconcileRow{Error: live + "; and more"}},
		{name: "waiting row", row: enterpriseHookReconcileRow{Error: enterpriseHookAwaitingSignInPrefix + ": " + live}},
		{name: "succeeded", row: enterpriseHookReconcileRow{OK: true, Error: live}},
		{name: "pending", row: enterpriseHookReconcileRow{Pending: true, Error: live}},
		{name: "runtime evidence", row: enterpriseHookReconcileRow{Error: live, Result: &enterprisehooks.InstallResult{}}},
	} {
		folder, ok := enterpriseHookSignedOutUntrustedFolder(tc.row, dataDir)
		if ok != (tc.folder != "") || folder != tc.folder {
			t.Errorf("%s: got %q, %t; want %q", tc.name, folder, ok, tc.folder)
		}
	}
	if _, ok := enterpriseHookSignedOutUntrustedFolder(enterpriseHookReconcileRow{Error: live}, ""); ok {
		t.Fatal("a target without a DefenseClaw folder matched")
	}
}
