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
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// hookGuardianRestoresFile records, in the guardian's data directory, when
// the standalone hook guardian (Windows, Linux, macOS) last put back each
// target's hooks
// because they no longer verified, for example after a standard user
// emptied the hooks block of their Hermes config. An agent reads its hooks
// when it starts, and Hermes keeps the callbacks it loaded for the life of
// the process: a session started while the hooks were gone kept running
// without DefenseClaw after the guardian restored the file, while status
// and verify read complete (GAP-0440 on Windows, GAP-0499 on Linux and
// macOS). Status, verify and ensure name that account's sessions of the
// connector that started before the restore. A Windows target is keyed by
// its SID, a Linux or macOS one by its uid.
//
// It is its own file: the guardian's state and authorization records keep
// the schema a prior binary reads strictly.
const hookGuardianRestoresFile = "hook_guardian_restores.json"

// hookGuardianRestoresMaxBytes bounds the record, which holds one entry per
// enrolled target at most.
const hookGuardianRestoresMaxBytes = 1 << 20

type enterpriseHookGuardianRestore struct {
	SID        string `json:"sid,omitempty"`
	UID        *int   `json:"uid,omitempty"`
	User       string `json:"user,omitempty"`
	Connector  string `json:"connector"`
	RestoredAt string `json:"restored_at"`
}

type enterpriseHookGuardianRestoreRecord struct {
	Version int                             `json:"version"`
	Targets []enterpriseHookGuardianRestore `json:"targets"`
}

// enterpriseHookGuardianRestoresEnabled is true for the standalone guardian
// only; on Secure Client the guardian writes no restore record.
var enterpriseHookGuardianRestoresEnabled = func() bool { return false }

func enterpriseHookGuardianRestoreKey(sid, connectorName string) string {
	return windowsEnterpriseManifestRowKey(enterprisehooks.ManifestTarget{SID: sid, Connector: connectorName})
}

// enterpriseHookGuardianRestoreUIDKey keys a Linux or macOS target.
func enterpriseHookGuardianRestoreUIDKey(uid int, connectorName string) string {
	return "uid:" + strconv.Itoa(uid) + "\x00" + strings.ToLower(strings.TrimSpace(connectorName))
}

// key is the entry's SID key, its uid key, or "" for an entry that names
// neither.
func (entry enterpriseHookGuardianRestore) key() string {
	if sid := strings.TrimSpace(entry.SID); sid != "" {
		return enterpriseHookGuardianRestoreKey(sid, entry.Connector)
	}
	if entry.UID != nil && *entry.UID > 0 {
		return enterpriseHookGuardianRestoreUIDKey(*entry.UID, entry.Connector)
	}
	return ""
}

// enterpriseHookGuardianRestoreUserKey names a Linux or macOS target by
// account name and connector, or "" without a name.
func enterpriseHookGuardianRestoreUserKey(user, connectorName string) string {
	user = strings.TrimSpace(user)
	if user == "" {
		return ""
	}
	return "user:" + user + "\x00" + strings.ToLower(strings.TrimSpace(connectorName))
}

// enterpriseHookGuardianRestoreRowKey keys a reconcile row like its entry.
func enterpriseHookGuardianRestoreRowKey(row enterpriseHookReconcileRow) string {
	entry := enterpriseHookGuardianRestore{SID: row.SID, Connector: row.Connector}
	if row.UID > 0 {
		uid := row.UID
		entry.UID = &uid
	}
	return entry.key()
}

// recordEnterpriseHookGuardianRestores dates the targets this reconcile put
// back (restored, from rows that verified before and were repaired) and
// keeps the earlier entries of the other targets in rows. An entry whose
// target left the manifest is dropped, so the record stays bounded. A row
// this pass could not resolve to a uid (a pending or failed identity lookup
// on Linux or macOS, for example during a directory outage) still enrolls
// its account's target, so its entry stays: dropping it lost the restore of
// a still-running session for good, as later clean passes repair nothing
// (GAP-0499). A row whose account identity changed (RevokeProtection) keeps
// nothing: the old uid may belong to another account now. It is best
// effort: a failed write is logged and changes nothing else.
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
	unresolved := map[string]bool{}
	for _, row := range rows {
		if key := enterpriseHookGuardianRestoreRowKey(row); key != "" {
			enrolled[key] = true
		} else if key := enterpriseHookGuardianRestoreUserKey(row.User, row.Connector); key != "" && !row.RevokeProtection {
			unresolved[key] = true
		}
	}
	entries := map[string]enterpriseHookGuardianRestore{}
	changed := false
	if record, err := readEnterpriseHookGuardianRestoreRecord(path); err == nil {
		for _, entry := range record.Targets {
			key := entry.key()
			if key == "" || (!enrolled[key] && !unresolved[enterpriseHookGuardianRestoreUserKey(entry.User, entry.Connector)]) {
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
		entry.SID = strings.ToUpper(strings.TrimSpace(entry.SID))
		entry.Connector = strings.ToLower(strings.TrimSpace(entry.Connector))
		key := entry.key()
		if key == "" {
			continue
		}
		entries[key] = entry
		changed = true
	}
	if !changed {
		return
	}
	record := enterpriseHookGuardianRestoreRecord{Version: 1, Targets: make([]enterpriseHookGuardianRestore, 0, len(entries))}
	for _, entry := range entries {
		record.Targets = append(record.Targets, entry)
	}
	sort.Slice(record.Targets, func(i, j int) bool { return record.Targets[i].key() < record.Targets[j].key() })
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
// each target's hooks, keyed as windowsEnterpriseManifestRowKey (Windows) or
// enterpriseHookGuardianRestoreUIDKey; nil when there is no readable record.
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
		key := entry.key()
		if err != nil || key == "" {
			continue
		}
		restores[key] = at
	}
	return restores
}
