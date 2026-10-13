// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func enableEnterpriseHookGuardianRestores(t *testing.T, enabled bool) {
	t.Helper()
	previous, previousOwnership := enterpriseHookGuardianRestoresEnabled, enterpriseHookAuthorizationOwnershipSetter
	t.Cleanup(func() {
		enterpriseHookGuardianRestoresEnabled, enterpriseHookAuthorizationOwnershipSetter = previous, previousOwnership
	})
	enterpriseHookGuardianRestoresEnabled = func() bool { return enabled }
	// The Windows protected-file writer hands the record to the gateway
	// service account, which a test host does not have.
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
}

func readGuardianRestoreRecordForTest(t *testing.T, dataDir string) enterpriseHookGuardianRestoreRecord {
	t.Helper()
	record, err := readEnterpriseHookGuardianRestoreRecord(filepath.Join(dataDir, hookGuardianRestoresFile))
	if err != nil {
		t.Fatalf("read restore record: %v", err)
	}
	return record
}

// GAP-0440: the guardian dates each target it put back, keeps the entries of
// the other enrolled targets and drops those of targets that left the
// manifest; a pass that restored nothing writes nothing.
func TestEnterpriseHookGuardianRestoresRecordEachRestoredTarget(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	dataDir := t.TempDir()
	const std1, std2 = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	rows := []enterpriseHookReconcileRow{
		{SID: std1, Connector: "hermes", OK: true},
		{SID: std2, Connector: "hermes", OK: true},
		{SID: std2, Connector: "codex", OK: true},
	}
	first := time.Date(2026, 10, 13, 13, 24, 30, 0, time.UTC)
	var log bytes.Buffer
	recordEnterpriseHookGuardianRestores(&log, dataDir, rows, []enterpriseHookGuardianRestore{
		{SID: strings.ToLower(std1), Connector: "Hermes", RestoredAt: first.Format(time.RFC3339Nano)},
	})
	restores := readEnterpriseHookGuardianRestores(dataDir)
	if len(restores) != 1 || !restores[enterpriseHookGuardianRestoreKey(std1, "hermes")].Equal(first) {
		t.Fatalf("restores after the first repair = %v, want hermes of %s at %s", restores, std1, first)
	}

	// A later pass restores another target; the first entry is kept.
	second := first.Add(10 * time.Minute)
	recordEnterpriseHookGuardianRestores(&log, dataDir, rows, []enterpriseHookGuardianRestore{
		{SID: std2, Connector: "codex", RestoredAt: second.Format(time.RFC3339Nano)},
	})
	restores = readEnterpriseHookGuardianRestores(dataDir)
	if len(restores) != 2 || !restores[enterpriseHookGuardianRestoreKey(std1, "hermes")].Equal(first) ||
		!restores[enterpriseHookGuardianRestoreKey(std2, "codex")].Equal(second) {
		t.Fatalf("restores after the second repair = %v", restores)
	}

	// A pass that restored nothing leaves the record as it was.
	path := filepath.Join(dataDir, hookGuardianRestoresFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, stale, stale); err != nil {
		t.Fatal(err)
	}
	recordEnterpriseHookGuardianRestores(&log, dataDir, rows, nil)
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("a pass without restores rewrote the record: %q (%v)", after, err)
	}
	if info, err := os.Stat(path); err != nil || !info.ModTime().Equal(stale) {
		t.Fatalf("a pass without restores touched the record: %v %v", info, err)
	}

	// std1 left the manifest: its entry is dropped.
	recordEnterpriseHookGuardianRestores(&log, dataDir, rows[1:], nil)
	record := readGuardianRestoreRecordForTest(t, dataDir)
	if len(record.Targets) != 1 || record.Targets[0].SID != std2 || record.Targets[0].Connector != "codex" {
		t.Fatalf("record after std1 left = %+v, want only codex of %s", record.Targets, std2)
	}
	if log.Len() != 0 {
		t.Fatalf("unexpected log: %q", log.String())
	}
}

// Outside the standalone Windows guardian (Secure Client, Linux, macOS) no
// record is written.
func TestEnterpriseHookGuardianRestoresWriteNothingWhenDisabled(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, false)
	dataDir := t.TempDir()
	recordEnterpriseHookGuardianRestores(os.Stderr, dataDir,
		[]enterpriseHookReconcileRow{{SID: "S-1-5-21-1-2-3-1001", Connector: "hermes", OK: true}},
		[]enterpriseHookGuardianRestore{{SID: "S-1-5-21-1-2-3-1001", Connector: "hermes", RestoredAt: time.Now().UTC().Format(time.RFC3339Nano)}})
	if _, err := os.Lstat(filepath.Join(dataDir, hookGuardianRestoresFile)); !os.IsNotExist(err) {
		t.Fatalf("disabled guardian wrote a restore record (err = %v)", err)
	}
}

// A record status cannot trust is read as no restores; the next restore
// replaces it.
func TestEnterpriseHookGuardianRestoresReadRejectsBadRecords(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, hookGuardianRestoresFile)
	for _, body := range []string{
		"not json",
		`{"version":2,"targets":[{"sid":"S-1-5-21-1-2-3-1001","connector":"hermes","restored_at":"2026-10-13T13:24:30Z"}]}`,
		strings.Repeat(" ", hookGuardianRestoresMaxBytes+1),
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if restores := readEnterpriseHookGuardianRestores(dataDir); len(restores) != 0 {
			t.Fatalf("restores from %.40q = %v, want none", body, restores)
		}
	}
	at := time.Date(2026, 10, 13, 13, 24, 30, 0, time.UTC)
	recordEnterpriseHookGuardianRestores(os.Stderr, dataDir,
		[]enterpriseHookReconcileRow{{SID: "S-1-5-21-1-2-3-1001", Connector: "hermes", OK: true}},
		[]enterpriseHookGuardianRestore{{SID: "S-1-5-21-1-2-3-1001", Connector: "hermes", RestoredAt: at.Format(time.RFC3339Nano)}})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record enterpriseHookGuardianRestoreRecord
	if err := json.Unmarshal(data, &record); err != nil || record.Version != 1 || len(record.Targets) != 1 {
		t.Fatalf("replaced record = %q (%v)", data, err)
	}
}
