// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// hookGuardianNoticesFile records, in the guardian's data directory, the
// protected targets whose agent config the last standalone Linux or macOS
// reconcile found put back from a copy or recreated with DefenseClaw's hooks
// only (connector.AgentConfigStatus, GAP-0564: a missing Hermes config.yaml
// lost the account's model and Bedrock settings while verify read ok). The
// enterprise status and verify warn about each. It is its own file: the
// guardian's state keeps the schema a prior binary reads strictly. Root
// only, like the repair and restore records.
const hookGuardianNoticesFile = "hook_guardian_notices.json"

type enterpriseHookGuardianNotice struct {
	User      string `json:"user"`
	UID       int    `json:"uid,omitempty"`
	Connector string `json:"connector"`
	// AgentConfig is a connector.AgentConfigStatus code, never free text:
	// the per-user worker that reports it runs as the account.
	AgentConfig string `json:"agent_config"`
}

type enterpriseHookGuardianNoticeRecord struct {
	Version   int                            `json:"version"`
	UpdatedAt string                         `json:"updated_at"`
	Targets   []enterpriseHookGuardianNotice `json:"targets"`
}

// writeEnterpriseHookGuardianNotices replaces the record with this pass's
// notices. A pass with none removes it; an unchanged set is not rewritten.
// It is best effort: only status and verify read it.
func writeEnterpriseHookGuardianNotices(dataDir string, notices []enterpriseHookGuardianNotice) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return
	}
	path := filepath.Join(dataDir, hookGuardianNoticesFile)
	kept := notices[:0:0]
	for _, notice := range notices {
		if notice.AgentConfig != "" && connector.ValidAgentConfigStatus(notice.AgentConfig) {
			kept = append(kept, notice)
		}
	}
	if len(kept) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: remove the agent config notices %s: %v\n", path, err)
		}
		return
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].User != kept[j].User {
			return kept[i].User < kept[j].User
		}
		return kept[i].Connector < kept[j].Connector
	})
	targets, _ := json.Marshal(kept)
	if previous, err := os.ReadFile(path); err == nil {
		var record enterpriseHookGuardianNoticeRecord
		if json.Unmarshal(previous, &record) == nil {
			if again, err := json.Marshal(record.Targets); err == nil && bytes.Equal(again, targets) {
				return
			}
		}
	}
	data, err := json.Marshal(enterpriseHookGuardianNoticeRecord{Version: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), Targets: kept})
	if err == nil {
		err = writeEnterpriseHookProtectedFile(path, append(data, '\n'))
	}
	if err != nil {
		fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: record the agent config notices in %s: %v\n", path, err)
	}
}
