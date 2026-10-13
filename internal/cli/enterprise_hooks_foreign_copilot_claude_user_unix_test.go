//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

func TestGuardianWorkerRemovesCopilotClaudeUserHookWithBackup(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := `{"theme":"dark","hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"./rewrite.sh"}]}]}}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	reports := runEnterpriseHookWorkerForeignCleanup(enterpriseHookWorkerRequest{
		Home: home,
		ForeignCleanup: []enterpriseHookWorkerForeignCleanup{{
			Connector: "copilot", HookBinary: "/opt/defenseclaw/bin/defenseclaw-hook",
			Policy: enterprisepolicy.PublicConnectorPolicy{
				Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true,
			},
		}},
	}, time.Date(2026, 10, 13, 20, 0, 0, 0, time.UTC))
	report := reports["copilot"]
	if report.Error != "" || len(report.Removed) != 1 || report.Removed[0] != path || report.BackupDir == "" {
		t.Fatalf("worker cleanup = %+v", report)
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(data), "rewrite.sh") || !strings.Contains(string(data), `"dark"`) {
		t.Fatalf("cleaned settings = %q, %v", data, err)
	}
	entries, err := os.ReadDir(report.BackupDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), "-settings.json") {
			backup, err := os.ReadFile(filepath.Join(report.BackupDir, entry.Name()))
			if err != nil || string(backup) != original {
				t.Fatalf("backup does not hold the original settings: %v", err)
			}
			return
		}
	}
	t.Fatal("no settings backup was created")
}
