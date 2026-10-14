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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-0564: the guardian recreated a missing Hermes config.yaml with its
// hooks only and status and verify read ok while the account's model and
// Bedrock settings were gone. A protected target whose agent config lost the
// account's settings is now reported for that account (the hooks are in
// place, so the host stays security-complete and verify passes).
func TestStatusAndVerifyReportAgentSettingsTheGuardianCouldNotPutBack(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			ledger, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true, "target_count": 2, "success_count": 2, "failure_count": 0})
			h.publishLedger(ledger)
			notice := "Hermes config /home/ctr1/.hermes/config.yaml went missing and DefenseClaw had no copy of it to put back, so it holds DefenseClaw's hooks only: the account's model and provider settings must be entered again (since 2026-10-14T05:48:49Z)"
			results := []map[string]any{
				{"user": "alice", "connector": "codex", "ok": true, "result": map[string]any{"connector": "codex"}},
				{"user": "ctr1", "user_home": "/home/ctr1", "connector": "hermes", "ok": true, "result": map[string]any{"connector": "hermes", "notices": []string{notice}}},
			}
			state, _ := json.Marshal(map[string]any{"results": results})
			receipt, _ := json.Marshal(map[string]any{"updated_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), "failure_count": 0})
			for path, data := range map[string][]byte{filepath.Join(h.env.Layout.DataDir, guardianStateFile): state, filepath.Join(h.env.Layout.GuardianAuthDir, guardianActivationFile): receipt} {
				if err := os.WriteFile(h.env.P(path), data, 0o640); err != nil {
					t.Fatal(err)
				}
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				r := h.run(Options{Action: action})
				requireOK(t, r)
				got := messagesOf(r.Warnings, codeAgentSettingsNotRestored)
				if !strings.Contains(got, "hermes for user ctr1: Hermes config /home/ctr1/.hermes/config.yaml went missing") || !strings.Contains(got, "must be entered again") {
					t.Fatalf("%s warnings = %+v", action, r.Warnings)
				}
				if strings.Contains(got, "alice") {
					t.Fatalf("%s names an account without a notice: %q", action, got)
				}
				if !r.SecurityComplete || hasWarning(r, codeGuardianTargetFailed) {
					t.Fatalf("%s: a lost agent setting is reported as a protection failure: %+v", action, r.Warnings)
				}
			}
		})
	}
}
