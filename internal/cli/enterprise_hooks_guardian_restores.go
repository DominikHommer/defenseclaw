// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// hookGuardianRestoresFile records, in the guardian's data directory, when
// the standalone Windows hook guardian last put back each target's hooks
// because they no longer verified, for example after a standard user
// emptied the hooks block of their Hermes config. An agent reads its hooks
// when it starts, and Hermes keeps the callbacks it loaded for the life of
// the process: a session started while the hooks were gone kept running
// without DefenseClaw after the guardian restored the file, while status
// and verify read complete (GAP-0440). Status, verify and ensure name that
// account's sessions of the connector that started before the restore.
//
// It is its own file: the guardian's state and authorization records keep
// the schema a prior binary reads strictly.
const hookGuardianRestoresFile = "hook_guardian_restores.json"

// hookGuardianRestoresMaxBytes bounds the record, which holds one entry per
// enrolled target at most.
const hookGuardianRestoresMaxBytes = 1 << 20

type enterpriseHookGuardianRestore struct {
	SID        string `json:"sid"`
	Connector  string `json:"connector"`
	RestoredAt string `json:"restored_at"`
}

type enterpriseHookGuardianRestoreRecord struct {
	Version int                             `json:"version"`
	Targets []enterpriseHookGuardianRestore `json:"targets"`
}

// enterpriseHookGuardianRestoresEnabled is true for the standalone Windows
// guardian only; elsewhere, and on Secure Client, the guardian writes no
// restore record.
var enterpriseHookGuardianRestoresEnabled = func() bool { return false }

func enterpriseHookGuardianRestoreKey(sid, connectorName string) string {
	return windowsEnterpriseManifestRowKey(enterprisehooks.ManifestTarget{SID: sid, Connector: connectorName})
}

// recordEnterpriseHookGuardianRestores dates the targets this reconcile put
// back (restored, from rows that verified before and were repaired) and
// keeps the earlier entries of the other targets in rows. An entry whose
// target left the manifest is dropped, so the record stays bounded. It is
// best effort: a failed write is logged and changes nothing else.
func recordEnterpriseHookGuardianRestores(
	stderr io.Writer,
	dataDir string,
	rows []enterpriseHookReconcileRow,
	restored []enterpriseHookGuardianRestore,
) {
	dataDir = strings.TrimSpace(dataDir)
	if !enterpriseHookGuardianRestoresEnabled() || dataDir == "" {
		return
	}
	path := filepath.Join(dataDir, hookGuardianRestoresFile)
	enrolled := make(map[string]bool, len(rows))
	for _, row := range rows {
		if sid := strings.TrimSpace(row.SID); sid != "" {
			enrolled[enterpriseHookGuardianRestoreKey(sid, row.Connector)] = true
		}
	}
	entries := map[string]enterpriseHookGuardianRestore{}
	changed := false
	if record, err := readEnterpriseHookGuardianRestoreRecord(path); err == nil {
		for _, entry := range record.Targets {
			key := enterpriseHookGuardianRestoreKey(entry.SID, entry.Connector)
			if !enrolled[key] {
				changed = true
				continue
			}
			entries[key] = entry
		}
	} else if !os.IsNotExist(err) {
		// An unreadable record is replaced by this pass's entries.
		changed = true
	}
	for _, entry := range restored {
		sid := strings.ToUpper(strings.TrimSpace(entry.SID))
		if sid == "" {
			continue
		}
		key := enterpriseHookGuardianRestoreKey(sid, entry.Connector)
		entries[key] = enterpriseHookGuardianRestore{
			SID:        sid,
			Connector:  strings.ToLower(strings.TrimSpace(entry.Connector)),
			RestoredAt: entry.RestoredAt,
		}
		changed = true
	}
	if !changed {
		return
	}
	record := enterpriseHookGuardianRestoreRecord{Version: 1, Targets: make([]enterpriseHookGuardianRestore, 0, len(entries))}
	for _, entry := range entries {
		record.Targets = append(record.Targets, entry)
	}
	sort.Slice(record.Targets, func(i, j int) bool {
		if record.Targets[i].SID != record.Targets[j].SID {
			return record.Targets[i].SID < record.Targets[j].SID
		}
		return record.Targets[i].Connector < record.Targets[j].Connector
	})
	data, err := json.Marshal(record)
	if err == nil {
		err = writeEnterpriseHookProtectedFile(path, append(data, '\n'))
	}
	if err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] warn: could not record the restored targets in %s: %v\n", path, err)
	}
}

func readEnterpriseHookGuardianRestoreRecord(path string) (enterpriseHookGuardianRestoreRecord, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return enterpriseHookGuardianRestoreRecord{}, err
	}
	data, err := readEnterpriseHookBoundedFile(path, info, hookGuardianRestoresMaxBytes, "hook guardian restore record")
	if err != nil {
		return enterpriseHookGuardianRestoreRecord{}, err
	}
	var record enterpriseHookGuardianRestoreRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return enterpriseHookGuardianRestoreRecord{}, err
	}
	if record.Version != 1 {
		return enterpriseHookGuardianRestoreRecord{}, fmt.Errorf("hook guardian restore record has version %d", record.Version)
	}
	return record, nil
}

// readEnterpriseHookGuardianRestores returns when the guardian last put back
// each target's hooks, keyed as windowsEnterpriseManifestRowKey; nil when
// there is no readable record.
func readEnterpriseHookGuardianRestores(dataDir string) map[string]time.Time {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil
	}
	record, err := readEnterpriseHookGuardianRestoreRecord(filepath.Join(dataDir, hookGuardianRestoresFile))
	if err != nil {
		return nil
	}
	restores := make(map[string]time.Time, len(record.Targets))
	for _, entry := range record.Targets {
		at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(entry.RestoredAt))
		if err != nil || strings.TrimSpace(entry.SID) == "" {
			continue
		}
		restores[enterpriseHookGuardianRestoreKey(entry.SID, entry.Connector)] = at
	}
	return restores
}
