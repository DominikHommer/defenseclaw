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

package enterpriseunix

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// failingReconcileRunner fails `enterprise hooks reconcile` with err.
type failingReconcileRunner struct {
	Runner
	err error
}

func (r failingReconcileRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if strings.HasPrefix(strings.Join(args, " "), "enterprise hooks reconcile ") {
		return CommandResult{ExitCode: 1}, r.err
	}
	return r.Runner.Run(ctx, name, args...)
}

// A registration the hook guardian still has to remove from a user's home
// (its per-user cleanup ledger) is reported by status and verify as a
// warning that does not fail verify.
func TestGuardianCleanupPendingIsReported(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	authDir := h.env.P(h.env.Layout.GuardianAuthDir)
	ledger, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true, "target_count": 0, "success_count": 0, "failure_count": 0})
	cleanup, _ := json.Marshal(map[string]any{"version": 1, "pending": []map[string]any{
		{"connector": "kiro", "sid": "", "uid": 1001, "user": "alice", "user_home": "/home/alice"},
	}})
	h.publishLedger(ledger)
	if err := os.WriteFile(filepath.Join(authDir, managed.HookGuardianUserCleanupFile), cleanup, 0o640); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		requireOK(t, result)
		if got := messagesOf(result.Warnings, codeGuardianCleanupPending); !strings.Contains(got, "kiro") || !strings.Contains(got, "alice") {
			t.Fatalf("%s does not report the pending cleanup: %+v", action, result.Warnings)
		}
	}
}

// The deleted-account warning must not hide a real failure, and must not
// blame a deleted account for a directory outage. A failure of an account
// that still exists stays a failure, whatever its text. An account that
// does not resolve is not a protection failure; it is reported as removed
// only when the enumerator confirmed it is gone: a local account, or a
// counted definitive miss. A directory account the enumerator could not
// confirm (the directory does not answer, GAP-0593) is neither, and whatever
// the reconcile error (a removed home, GAP-0692) it never fails the host.
func TestAccountRemovedWarningNeedsAConfirmedMiss(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.accounts.accounts["alice"] = Account{Name: "alice", UID: 1500, GID: 1500}
	writeEnumeratorState(t, h,
		map[string]string{"gone1": "files", "gone2": "directory", "gone3": "directory"},
		map[string]int{"gone3\x00codex": 1})
	quoted := `parse Codex config for hook guardian: toml: key does not exist: no such account is already defined`
	for _, tc := range []struct {
		name, user, message string
		removed, failed     bool
	}{
		{"a user's file text for an existing account", "alice", quoted, false, true},
		{"the exact error for an account that still exists", "alice", `enterprise hooks: target account "alice" does not exist: no such account`, false, true},
		{"a missing local account", "gone1", `enterprise hooks: target account "gone1" does not exist: no such account`, true, false},
		{"a missing directory account not confirmed", "gone2", `enterprise hooks: target account "gone2" does not exist: no such account`, false, false},
		{"a confirmed directory account whose home is gone", "gone3", "user home /home/gone3 is not available yet: no such file or directory", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, _ := json.Marshal(map[string]any{"results": []map[string]any{
				{"user": tc.user, "connector": "codex", "ok": false, "error": tc.message},
			}})
			if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), state, 0o640); err != nil {
				t.Fatal(err)
			}
			status := h.run(Options{Action: ActionStatus})
			if got := hasWarning(status, codeGuardianTargetAccountRemoved); got != tc.removed {
				t.Fatalf("account-removed warning = %v, want %v: %+v", got, tc.removed, status.Warnings)
			}
			if got := hasWarning(status, codeGuardianTargetFailed); got != tc.failed {
				t.Fatalf("target-failed warning = %v, want %v: %+v", got, tc.failed, status.Warnings)
			}
		})
	}
}

// writeEnumeratorState writes the hook enumerator state beside targets.yaml.
func writeEnumeratorState(t *testing.T, h *testHost, sources map[string]string, misses map[string]int) {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"version": 1, "sources": sources, "misses": misses})
	path := h.env.P(filepath.Join(filepath.Dir(h.env.Layout.ManifestPath), enumeratorStateFile))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
}

// GAP-0515: with the service account removed by configuration management,
// verify said only that it was missing, and repair recreated it and restored
// the owners of its folders but reported no changes.
func TestRepairReportsTheRecreatedServiceAccountAndItsFolders(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	delete(h.accounts.accounts, h.env.Layout.ServiceUser)
	verify := h.run(Options{Action: ActionVerify})
	if got := messagesOf(verify.Errors, codeVerify); !strings.Contains(got, "is missing") || !strings.Contains(got, " repair` recreates it") {
		t.Fatalf("verify does not name repair: %s", got)
	}
	repair := h.run(Options{Action: ActionRepair})
	requireOK(t, repair)
	got := strings.Join(repair.Changes, "\n")
	if !strings.Contains(got, "created the service account "+h.env.Layout.ServiceUser) || !strings.Contains(got, "restored the mode and owner of "+h.env.Layout.DataDir) {
		t.Fatalf("repair changes = %q", repair.Changes)
	}
}
