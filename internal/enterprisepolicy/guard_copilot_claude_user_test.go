// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Copilot reads Claude-format user hooks even when a project root stops the
// ancestor walk before it reaches the user's home.
func TestCopilotGuardsClaudeUserSettingsOutsideTheProject(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
			req.GOOS = goos
			path := filepath.Join(req.Home, ".claude", "settings.json")
			writeFile(t, path, foreignClaudeSettings)
			decision := EvaluateForeignHooks(req)
			if !decision.Deny || len(decision.Findings) != 1 || decision.Findings[0].Scope != ScopeUser || decision.Findings[0].Path != path ||
				!strings.Contains(decision.Reason, path) || !strings.Contains(decision.Reason, "connectors.copilot.allowed_hooks") {
				t.Fatalf("Copilot user hook decision = %+v", decision)
			}
		})
	}
}

func TestCopilotGuardianRemovesClaudeUserHookWithBackup(t *testing.T) {
	req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
	path := filepath.Join(req.Home, ".claude", "settings.json")
	original := `{"theme":"dark","hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"./rewrite.sh"}]}]}}`
	writeFile(t, path, original)
	when := time.Date(2026, 10, 13, 20, 0, 0, 0, time.UTC)
	result, err := CleanUserForeignHooks(req, when)
	if err != nil || len(result.Removed) != 1 || result.Removed[0].Path != path || result.BackupDir == "" {
		t.Fatalf("cleanup = %+v, %v", result, err)
	}
	if data, err := os.ReadFile(path); err != nil || strings.Contains(string(data), "rewrite.sh") || !strings.Contains(string(data), `"dark"`) {
		t.Fatalf("rewritten settings = %q, %v", data, err)
	}
	entries, err := os.ReadDir(result.BackupDir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("backup entries = %v, %v", entries, err)
	}
	var backupPath string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), "-settings.json") {
			backupPath = filepath.Join(result.BackupDir, entry.Name())
		}
	}
	backup, err := os.ReadFile(backupPath)
	if err != nil || string(backup) != original {
		t.Fatalf("backup is not the exact original settings: %v", err)
	}
	if decision := EvaluateForeignHooks(req); decision.Deny {
		t.Fatalf("cleaned settings still deny: %+v", decision)
	}
}
