// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-0499: the standalone Linux and macOS guardian dates, by uid, the
// targets its pass put back (the pass's repair record names them by account
// and connector); a repair record left by an earlier pass is not this
// pass's restore.
func TestEnterpriseHookStandaloneUnixRestoresDateThePassRepairs(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	dataDir := t.TempDir()
	rows := []enterpriseHookReconcileRow{
		{User: "alice", UID: 1001, Connector: "hermes", OK: true},
		{User: "alice", UID: 1001, Connector: "codex", OK: true},
		{User: "bob", UID: 1002, Connector: "hermes", OK: true},
	}
	writeRepairs := func(at time.Time, users ...string) {
		t.Helper()
		type repair struct {
			User      string `json:"user"`
			Connector string `json:"connector"`
		}
		var repaired []repair
		for _, user := range users {
			repaired = append(repaired, repair{User: user, Connector: "hermes"})
		}
		data, err := json.Marshal(struct {
			UpdatedAt string   `json:"updated_at"`
			Repaired  []repair `json:"repaired"`
		}{at.UTC().Format(time.RFC3339Nano), repaired})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, hookGuardianRepairsFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	since := time.Now().Add(-time.Second)
	repairedAt := since.Add(500 * time.Millisecond)
	writeRepairs(repairedAt, "alice")
	recordEnterpriseHookStandaloneUnixRestores(io.Discard, dataDir, since, enterpriseHookReconcileRun{Rows: rows, Repairs: 1})
	restores := readEnterpriseHookGuardianRestores(dataDir)
	if len(restores) != 1 || !restores[enterpriseHookGuardianRestoreUIDKey(1001, "hermes")].Equal(repairedAt.UTC()) {
		t.Fatalf("restores = %v, want hermes of uid 1001 at %s", restores, repairedAt)
	}
	record := readGuardianRestoreRecordForTest(t, dataDir)
	if len(record.Targets) != 1 || record.Targets[0].User != "alice" || record.Targets[0].SID != "" {
		t.Fatalf("record = %+v, want alice by uid", record.Targets)
	}

	// The next pass repaired bob but could not rewrite the repair record:
	// the earlier record is not taken for this pass.
	later := time.Now().Add(time.Second)
	recordEnterpriseHookStandaloneUnixRestores(io.Discard, dataDir, later, enterpriseHookReconcileRun{Rows: rows, Repairs: 1})
	if restores := readEnterpriseHookGuardianRestores(dataDir); len(restores) != 1 {
		t.Fatalf("restores after a pass without its own repair record = %v, want only alice's", restores)
	}

	// alice left the manifest: her entry is dropped by a pass without repairs.
	recordEnterpriseHookStandaloneUnixRestores(io.Discard, dataDir, later, enterpriseHookReconcileRun{Rows: rows[2:]})
	if restores := readEnterpriseHookGuardianRestores(dataDir); len(restores) != 0 {
		t.Fatalf("restores after alice left = %v, want none", restores)
	}
}
