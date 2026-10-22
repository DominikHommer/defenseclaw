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

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0578: one agent's own settings turning its hooks off (or not parsing)
// must not stop the gateway for the others. The start reports that connector
// with the reason, keeps its earlier hooks and the user's setting, and a start
// after the fix guards it again.
func TestRunGuardrailMultiAgentSettingsRefusalKeepsOtherConnectors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("per-user Codex setup on Windows needs protected executable evidence")
	}
	cases := []struct {
		name   string
		victim string
		peer   string
		off    func(t *testing.T, codexConfig, claudeSettings string)
		on     func(t *testing.T, codexConfig, claudeSettings string)
		reason string
	}{
		{
			name: "codex features hooks false", victim: "codex", peer: "claudecode",
			off: func(t *testing.T, codexConfig, _ string) {
				appendAgentFile(t, codexConfig, "\n[features]\nhooks = false\n")
			},
			on: func(t *testing.T, codexConfig, _ string) {
				replaceAgentFile(t, codexConfig, "hooks = false", "hooks = true")
			},
			reason: "codex features enable hooks",
		},
		{
			name: "codex retired codex_hooks false", victim: "codex", peer: "claudecode",
			off: func(t *testing.T, codexConfig, _ string) {
				appendAgentFile(t, codexConfig, "\n[features]\ncodex_hooks = false\n")
			},
			on: func(t *testing.T, codexConfig, _ string) {
				replaceAgentFile(t, codexConfig, "codex_hooks = false", "codex_hooks = true")
			},
			reason: "([features] codex_hooks = false)",
		},
		{
			name: "codex config does not parse", victim: "codex", peer: "claudecode",
			off:    func(t *testing.T, codexConfig, _ string) { appendAgentFile(t, codexConfig, "\nbroken = [\n") },
			on:     func(t *testing.T, codexConfig, _ string) { replaceAgentFile(t, codexConfig, "\nbroken = [\n", "\n") },
			reason: "does not parse",
		},
		{
			name: "claude code disableAllHooks", victim: "claudecode", peer: "codex",
			off:    func(t *testing.T, _, claudeSettings string) { setClaudeDisableAllHooks(t, claudeSettings, true) },
			on:     func(t *testing.T, _, claudeSettings string) { setClaudeDisableAllHooks(t, claudeSettings, false) },
			reason: "disableAllHooks=true",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			agentHome := testenv.PrivateTempDir(t)
			codexConfig := filepath.Join(agentHome, ".codex", "config.toml")
			claudeSettings := filepath.Join(agentHome, ".claude", "settings.json")
			for _, path := range []string{codexConfig, claudeSettings} {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(claudeSettings, []byte(`{"env":{"EDITOR":"operator-editor"}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"),
				[]byte(`{"agents":{"claudecode":{"version":"2.1.307 (Claude Code)"},"codex":{"version":"codex-cli 0.142.4"}}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			prevCodex, prevClaude := connector.CodexConfigPathOverride, connector.ClaudeCodeSettingsPathOverride
			connector.CodexConfigPathOverride, connector.ClaudeCodeSettingsPathOverride = codexConfig, claudeSettings
			t.Cleanup(func() {
				connector.CodexConfigPathOverride, connector.ClaudeCodeSettingsPathOverride = prevCodex, prevClaude
			})
			cfg := &config.Config{
				DataDir: dataDir,
				Gateway: config.GatewayConfig{APIPort: 18972},
				Guardrail: config.GuardrailConfig{
					Enabled: true,
					Mode:    "action",
					Connectors: map[string]config.PerConnectorGuardrailConfig{
						"codex":      {},
						"claudecode": {},
					},
				},
			}
			boot := func(t *testing.T) (*Sidecar, error) {
				t.Helper()
				s := &Sidecar{cfg: cfg, health: NewSidecarHealth(), router: routerWithDefaultRulePack(t)}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- s.runGuardrailMulti(ctx) }()
				deadline := time.Now().Add(time.Minute)
				for s.health.Snapshot().Guardrail.State != StateRunning {
					select {
					case err := <-done:
						return s, err
					case <-time.After(10 * time.Millisecond):
					}
					if time.Now().After(deadline) {
						cancel()
						<-done
						t.Fatal("the guardrail neither ran nor failed within a minute")
					}
				}
				cancel()
				return s, <-done
			}
			running := func(s *Sidecar) []string {
				names, _ := s.health.Snapshot().Guardrail.Details["connectors"].([]string)
				return names
			}

			s, err := boot(t)
			if err != nil || !reflect.DeepEqual(running(s), []string{"claudecode", "codex"}) {
				t.Fatalf("first start: err=%v running=%v", err, running(s))
			}
			lockPath := filepath.Join(dataDir, "hook_contract_lock.json")
			lockBefore := readAgentFile(t, lockPath)
			tc.off(t, codexConfig, claudeSettings)
			victimFile := codexConfig
			if tc.victim == "claudecode" {
				victimFile = claudeSettings
			}
			victimBefore := readAgentFile(t, victimFile)

			s, err = boot(t)
			if err != nil {
				t.Fatalf("one agent's settings stopped the gateway for every connector: %v", err)
			}
			snap := s.health.Snapshot()
			if snap.Guardrail.State != StateRunning || !reflect.DeepEqual(running(s), []string{tc.peer}) {
				t.Fatalf("guardrail state=%s running=%v (%s), want %s running", snap.Guardrail.State, running(s), snap.Guardrail.LastError, tc.peer)
			}
			refused := fmt.Sprint(snap.Guardrail.Details["connectors_refused_by_agent_settings"])
			if !strings.Contains(refused, tc.victim+":") || !strings.Contains(refused, tc.reason) {
				t.Errorf("health does not name %s and its fix %q: %s", tc.victim, tc.reason, refused)
			}
			if after := readAgentFile(t, victimFile); !bytes.Equal(after, victimBefore) {
				t.Errorf("the start rewrote the user's %s settings:\nbefore:\n%s\nafter:\n%s", tc.victim, victimBefore, after)
			}
			if !strings.Contains(string(readAgentFile(t, victimFile)), filepath.Join(dataDir, "hooks")) {
				t.Errorf("the start removed the earlier %s hooks", tc.victim)
			}
			if after := readAgentFile(t, lockPath); !bytes.Equal(jsonConnectorEntry(t, after, tc.victim), jsonConnectorEntry(t, lockBefore, tc.victim)) {
				t.Errorf("the start changed the %s hook contract lock entry", tc.victim)
			}

			tc.on(t, codexConfig, claudeSettings)
			s, err = boot(t)
			if err != nil || !reflect.DeepEqual(running(s), []string{"claudecode", "codex"}) {
				t.Fatalf("start after the fix: err=%v running=%v", err, running(s))
			}
			if refused, ok := s.health.Snapshot().Guardrail.Details["connectors_refused_by_agent_settings"]; ok {
				t.Errorf("start after the fix still reports %v", refused)
			}
		})
	}
}

func readAgentFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func appendAgentFile(t *testing.T, path, text string) {
	t.Helper()
	data := readAgentFile(t, path)
	if bytes.Contains(data, []byte("[features]")) {
		t.Fatalf("%s already has a [features] table", path)
	}
	if err := os.WriteFile(path, append(data, text...), 0o600); err != nil {
		t.Fatal(err)
	}
}

func replaceAgentFile(t *testing.T, path, old, new string) {
	t.Helper()
	data := readAgentFile(t, path)
	if !bytes.Contains(data, []byte(old)) {
		t.Fatalf("%s does not contain %q", path, old)
	}
	if err := os.WriteFile(path, bytes.Replace(data, []byte(old), []byte(new), 1), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setClaudeDisableAllHooks(t *testing.T, path string, disabled bool) {
	t.Helper()
	settings := map[string]interface{}{}
	if err := json.Unmarshal(readAgentFile(t, path), &settings); err != nil {
		t.Fatal(err)
	}
	settings["disableAllHooks"] = disabled
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func jsonConnectorEntry(t *testing.T, lock []byte, name string) []byte {
	t.Helper()
	var doc struct {
		Connectors map[string]json.RawMessage `json:"connectors"`
	}
	if err := json.Unmarshal(lock, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Connectors[name]
}
