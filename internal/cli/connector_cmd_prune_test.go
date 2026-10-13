// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const operatorClaudeSettings = `{"env":{"OPERATOR_FLAG":"1"},"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"/opt/operator/prompt-check.sh"}]}]}}`

// setUpClaudeCodeAfterOperator writes the operator's own Claude Code settings,
// then runs the claudecode Setup over them, as `defenseclaw setup claudecode`
// does, and returns the settings path.
func setUpClaudeCodeAfterOperator(t *testing.T, dataDir string) string {
	t.Helper()
	settingsPath := filepath.Join(testenv.PrivateTempDir(t), "settings.json")
	if err := os.WriteFile(settingsPath, []byte(operatorClaudeSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = previous })
	opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token"}
	if err := connector.NewClaudeCodeConnector().Setup(context.Background(), opts); err != nil {
		t.Fatalf("claudecode setup: %v", err)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), filepath.Join(dataDir, "hooks")) {
		t.Fatalf("setup wrote no DefenseClaw hook entries:\n%s", data)
	}
	return settingsPath
}

// rel-1-0-1:GAP-0009: a rollback restored the data directory from before
// claudecode was set up, so ~/.claude/settings.json kept DefenseClaw hook
// entries that run a hook script the restored install never had, and Claude
// Code blocked every prompt. prune-orphans removes those entries, and only
// those: the operator's hook and env stay.
func TestConnectorPruneOrphansRemovesHooksOfAConnectorRolledBackAway(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses the POSIX hook layout")
	}
	dataDir := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dataDir, "codex")()
	settingsPath := setUpClaudeCodeAfterOperator(t, dataDir)
	// The rollback: the data directory of the install before the setup.
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, exitCode := runConnectorCmd(t, "prune-orphans")
	if exitCode != 0 || strings.TrimSpace(stderr) != "" || !strings.Contains(stdout, "claudecode is not configured: removed") {
		t.Fatalf("prune-orphans: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	after, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), dataDir) || strings.Contains(strings.ToLower(string(after)), "defenseclaw") {
		t.Fatalf("DefenseClaw entries left in settings.json:\n%s", after)
	}
	var settings struct {
		Env   map[string]any `json:"env"`
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(after, &settings); err != nil {
		t.Fatalf("settings.json after prune: %v\n%s", err, after)
	}
	prompt := settings.Hooks["UserPromptSubmit"]
	if settings.Env["OPERATOR_FLAG"] != "1" || len(prompt) != 1 || len(prompt[0].Hooks) != 1 ||
		prompt[0].Hooks[0].Command != "/opt/operator/prompt-check.sh" {
		t.Fatalf("the operator's own settings changed:\n%s", after)
	}

	// Nothing is left to remove, so a second run says nothing.
	stdout, stderr, exitCode = runConnectorCmd(t, "prune-orphans")
	if exitCode != 0 || strings.TrimSpace(stdout+stderr) != "" {
		t.Fatalf("second prune-orphans: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

// A connector that config.yaml or the runtime connector state names is never
// an orphan, even while its hook script is missing (doctor reports that).
func TestConnectorPruneOrphansKeepsConfiguredConnectors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses the POSIX hook layout")
	}
	for _, source := range []string{"config", "runtime state"} {
		t.Run(source, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			primary := "codex"
			if source == "config" {
				primary = "claudecode"
			}
			defer withConnectorState(t, dataDir, primary)()
			settingsPath := setUpClaudeCodeAfterOperator(t, dataDir)
			if source == "runtime state" {
				if err := connector.SaveActiveConnectors(dataDir, []string{"claudecode"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(filepath.Join(dataDir, "hooks", "claude-code-hook.sh")); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}

			stdout, stderr, exitCode := runConnectorCmd(t, "prune-orphans", "--connector", "claudecode")
			if exitCode != 0 || strings.TrimSpace(stdout+stderr) != "" {
				t.Fatalf("prune-orphans: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
			after, err := os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("a configured connector's settings changed:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

// Without config.yaml nothing tells what is configured: nothing is removed.
func TestConnectorPruneOrphansNeedsTheConfig(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dataDir, "codex")()
	cfg = nil
	_, stderr, _ := runConnectorCmd(t, "prune-orphans")
	if !strings.Contains(stderr, "config.yaml is not loaded; nothing was removed") {
		t.Fatalf("stderr = %q", stderr)
	}
}
