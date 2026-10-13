// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-0499: a standard user emptied the hooks block of their Hermes config
// and started Hermes; the guardian put the hooks back, but that session kept
// running without them while status and verify read complete. Status and
// verify now name the account's Hermes sessions started before the restore
// and report security_complete false; a session started after the restore
// and a Codex session (Codex reads the managed requirements per turn) are
// not named.
func TestStatusNamesSessionsStartedBeforeAGuardianRestore(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	record, err := h.env.loadDeployment()
	if err != nil || record == nil {
		t.Fatalf("no deployment: %v", err)
	}
	activationTime := record.ActivatedAt
	if activationTime == "" {
		activationTime = record.InstalledAt
	}
	activated, err := time.Parse(time.RFC3339Nano, activationTime)
	if err != nil {
		t.Fatal(err)
	}
	writeHostFile(t, h, "/proc/stat", fmt.Sprintf("cpu 0 0 0 0\nbtime %d\n", activated.Unix()))
	agent := func(pid, cmdline string, ticks int64) {
		writeHostFile(t, h, "/proc/"+pid+"/cmdline", cmdline)
		writeHostFile(t, h, "/proc/"+pid+"/stat", fmt.Sprintf("%s (agent) S 1 %s %s%d 0 0", pid, pid, strings.Repeat("0 ", 16), ticks))
	}
	hermes := "/home/u/.hermes/tools/python/bin/python3\x00-I\x00-c\x00import os\nfrom hermes_cli.main import main\x00"
	agent("6001", hermes, 2*60*100)      // after the activation, before the restore
	agent("6002", hermes, 20*60*100)     // after the restore
	agent("6003", "codex\x00", 2*60*100) // Codex reads the requirements per turn
	baseline := h.run(Options{Action: ActionStatus})
	if got := messagesOf(baseline.Warnings, codeAgentSessionsRestart); got != "" {
		t.Fatalf("sessions started after the activation are named without a restore: %q", got)
	}
	uid := os.Getuid()
	restoredAt := activated.Add(10 * time.Minute).UTC()
	writeHostFile(t, h, filepath.Join(h.env.Layout.DataDir, guardianRestoresFile), fmt.Sprintf(
		`{"version":1,"targets":[{"uid":%d,"user":"u","connector":"hermes","restored_at":%q},{"uid":%d,"user":"u","connector":"codex","restored_at":%q}]}`,
		uid, restoredAt.Format(time.RFC3339Nano), uid, restoredAt.Format(time.RFC3339Nano)))
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		got := messagesOf(result.Warnings, codeAgentSessionsRestart)
		if !strings.Contains(got, "hermes (pid 6001)") ||
			!strings.Contains(got, "put back the account's changed or removed hermes hooks at "+restoredAt.Format(time.RFC3339)) ||
			strings.Contains(got, "6002") || strings.Contains(got, "6003") {
			t.Fatalf("%s does not name exactly the Hermes session started before the restore: %q", action, got)
		}
		if result.SecurityComplete {
			t.Fatalf("%s reports security_complete with a session started before the restore", action)
		}
	}
	// The user restarted Hermes: nothing is named.
	if err := os.RemoveAll(h.env.P("/proc/6001")); err != nil {
		t.Fatal(err)
	}
	if got := messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codeAgentSessionsRestart); got != "" {
		t.Fatalf("a restarted session is still named: %q", got)
	}
}
