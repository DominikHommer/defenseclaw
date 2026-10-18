// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0146: a target that waits for its signed-out account, or whose hook
// file is gone, is not security-complete in status or verify.
func TestWindowsEnterpriseGuardianTargetGapsClearSecurityComplete(t *testing.T) {
	home := t.TempDir()
	hookFile := filepath.Join(home, ".copilot", "hooks", "defenseclaw-vscode.json")
	if err := os.MkdirAll(filepath.Dir(hookFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookFile, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(home, ".copilot", "config.json")
	if err := os.WriteFile(configFile, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	verified := enterpriseHookReconcileRow{
		User: "dcw-std1", UserHome: home, SID: "S-1-5-21-1-2-3-1017", Connector: "copilot", OK: true,
		Result: &enterprisehooks.InstallResult{Connector: "copilot", HookConfigPaths: []string{configFile}},
	}
	files := func(row enterpriseHookReconcileRow) []string {
		return windowsEnterpriseGuardianRowHookFiles(row, []string{hookFile})
	}
	run := func(rows ...enterpriseHookReconcileRow) *enterprisestatus.Result {
		result := &enterprisestatus.Result{Action: "status", SecurityComplete: true}
		applyWindowsEnterpriseGuardianTargetGaps(result, enterpriseHookGuardianState{Results: rows}, files)
		return result
	}

	if result := run(verified, enterpriseHookReconcileRow{User: "dcw-std2", Connector: "copilot", Pending: true}); !result.SecurityComplete || len(result.Warnings) != 0 {
		t.Fatalf("verified and pending rows with their files: security_complete=%t warnings=%+v, want complete and none", result.SecurityComplete, result.Warnings)
	}

	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	result := run(verified)
	if result.SecurityComplete || len(result.Warnings) != 1 ||
		result.Warnings[0].Code != windowsEnterpriseGuardianRepairPendingCode ||
		!strings.Contains(result.Warnings[0].Message, hookFile) ||
		!strings.Contains(result.Warnings[0].Message, "dcw-std1 for copilot") {
		t.Fatalf("deleted hook file: security_complete=%t warnings=%+v, want incomplete with one guardian_repair_pending naming the file", result.SecurityComplete, result.Warnings)
	}

	waiting := enterpriseHookReconcileRow{
		User: "dcw-std1", UserHome: home, SID: verified.SID, Connector: "copilot",
		Error: enterpriseHookAwaitingSignInPrefix + ": DefenseClaw 1.0.2 protected it (verification: hook file missing)",
	}
	result = run(waiting)
	if result.SecurityComplete || len(result.Warnings) != 1 ||
		result.Warnings[0].Code != windowsEnterpriseGuardianRepairPendingCode ||
		!strings.Contains(result.Warnings[0].Message, "copilot for dcw-std1") {
		t.Fatalf("row waiting for sign-in: security_complete=%t warnings=%+v, want incomplete with one guardian_repair_pending", result.SecurityComplete, result.Warnings)
	}

	failed := waiting
	failed.Error = "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable"
	result = run(failed)
	if result.SecurityComplete || len(result.Warnings) != 0 {
		t.Fatalf("failed row: security_complete=%t warnings=%+v, want incomplete; the guardian status error names it", result.SecurityComplete, result.Warnings)
	}
}

func TestWindowsEnterpriseGuardianRowHookFilesListsEachFileOnce(t *testing.T) {
	a, b, c := filepath.FromSlash("/a/hooks.json"), filepath.FromSlash("/b/config.json"), filepath.FromSlash("/c/extra.json")
	row := enterpriseHookReconcileRow{Result: &enterprisehooks.InstallResult{HookConfigPaths: []string{b, a, " "}}}
	got := windowsEnterpriseGuardianRowHookFiles(row, []string{a, c})
	want := []string{a, b, c}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("files = %v, want %v", got, want)
	}
	if got := windowsEnterpriseGuardianRowHookFiles(enterpriseHookReconcileRow{}, nil); len(got) != 0 {
		t.Fatalf("row without a result: files = %v, want none", got)
	}
}
