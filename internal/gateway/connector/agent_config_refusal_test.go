// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0578: when the agent's own settings turn its hooks off or do not
// parse, Setup refuses before it writes anything, so a gateway start keeps
// the earlier hooks and the user's setting instead of rolling them back.
func TestSetupRefusesAgentSettingsBeforeAnyChange(t *testing.T) {
	cases := []struct {
		name     string
		conn     func() Connector
		settings string
		body     string
		point    func(t *testing.T, path string)
		reason   string
	}{
		{
			name: "codex features hooks false", conn: func() Connector { return NewCodexConnector() },
			settings: "config.toml", body: "model = \"gpt-5\"\n\n[features]\nhooks = false\n",
			point:  pointCodexConfig,
			reason: "turn them back on with: codex features enable hooks",
		},
		{
			name: "codex retired codex_hooks false", conn: func() Connector { return NewCodexConnector() },
			settings: "config.toml", body: "[features]\ncodex_hooks = false\n",
			point:  pointCodexConfig,
			reason: "([features] codex_hooks = false)",
		},
		{
			name: "codex config does not parse", conn: func() Connector { return NewCodexConnector() },
			settings: "config.toml", body: "model = [\n",
			point:  pointCodexConfig,
			reason: "does not parse",
		},
		{
			name: "codex hooks of an unsupported type", conn: func() Connector { return NewCodexConnector() },
			settings: "config.toml", body: "hooks = \"hooks.json\"\n",
			point:  pointCodexConfig,
			reason: "unsupported type",
		},
		{
			name: "claude code disableAllHooks", conn: func() Connector { return NewClaudeCodeConnector() },
			settings: "settings.json", body: `{"disableAllHooks": true}`,
			point: func(t *testing.T, path string) {
				previous := ClaudeCodeSettingsPathOverride
				ClaudeCodeSettingsPathOverride = path
				t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })
			},
			reason: "remove disableAllHooks",
		},
		{
			name: "copilot disableAllHooks", conn: func() Connector { return NewCopilotConnector() },
			settings: "settings.json", body: `{"disableAllHooks": true}`,
			point:  func(t *testing.T, path string) { t.Setenv("COPILOT_HOME", filepath.Dir(path)) },
			reason: "disableAllHooks=true",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			path := filepath.Join(t.TempDir(), tc.settings)
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.point(t, path)
			// Setup's own check, which `defenseclaw setup` asks before it
			// restarts the gateway, refuses the same settings (GAP-0615).
			if err := CheckAgentSettings(tc.conn(), SetupOpts{DataDir: dataDir}); !errors.Is(err, ErrAgentConfigRefusal) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("CheckAgentSettings = %v; want the refusal Setup gives, saying %q", err, tc.reason)
			}
			err := tc.conn().Setup(context.Background(), SetupOpts{
				DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok",
			})
			if !errors.Is(err, ErrSetupRefusedUnchanged) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("Setup = %v; want a refusal before any change that says %q", err, tc.reason)
			}
			entries, readErr := os.ReadDir(dataDir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, entry := range entries {
				// The lifecycle lock serializes Setup; it is not state.
				if !strings.HasSuffix(entry.Name(), ".lock") {
					t.Errorf("Setup wrote %s into the data dir before refusing", entry.Name())
				}
			}
			if after, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(after, []byte(tc.body)) {
				t.Errorf("Setup changed the agent's settings: %q (%v)", after, readErr)
			}
		})
	}
}

func pointCodexConfig(t *testing.T, path string) {
	previous := CodexConfigPathOverride
	CodexConfigPathOverride = path
	t.Cleanup(func() { CodexConfigPathOverride = previous })
}

// GAP-0615: the check changes nothing and passes settings that let the hooks
// run, and a managed install or a connector without such a refusal is not
// asked.
func TestCheckAgentSettingsPassesUsableSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	body := []byte("model = \"gpt-5\"\n\n[features]\nhooks = true\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	pointCodexConfig(t, path)
	if err := CheckAgentSettings(NewCodexConnector(), SetupOpts{DataDir: t.TempDir()}); err != nil {
		t.Fatalf("CheckAgentSettings(usable codex config) = %v", err)
	}
	if err := os.WriteFile(path, []byte("[broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckAgentSettings(NewCodexConnector(), SetupOpts{DataDir: t.TempDir(), ManagedEnterprise: true}); err != nil {
		t.Fatalf("CheckAgentSettings(managed) = %v; managed requirements decide there", err)
	}
	if err := CheckAgentSettings(NewCursorConnector(), SetupOpts{DataDir: t.TempDir()}); err != nil {
		t.Fatalf("CheckAgentSettings(cursor) = %v; cursor has no agent-settings refusal", err)
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != "[broken\n" {
		t.Fatalf("CheckAgentSettings changed the settings: %q (%v)", after, err)
	}
}
