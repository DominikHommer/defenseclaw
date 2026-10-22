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

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0615: `defenseclaw setup codex` with a config.toml that does not parse
// restarted the gateway, which then could not start Codex, and the rollback
// left the gateway stopped. Setup now asks this command first; it names the
// file and changes nothing.
func TestConnectorCheckAgentSettingsRefusesCodexConfigThatDoesNotParse(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dataDir, "codex")()
	path := filepath.Join(t.TempDir(), "config.toml")
	broken := "model = \"gpt-5\"\n[t6z2_broken\n"
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = path
	t.Cleanup(func() { connector.CodexConfigPathOverride = previous })

	stdout, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", "codex", "--json")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout is not JSON: %q (%v)", stdout, err)
	}
	reason, _ := payload["reason"].(string)
	if payload["refused"] != true || !strings.Contains(reason, path) || !strings.Contains(reason, "does not parse") {
		t.Fatalf("payload = %v; want a refusal naming %s", payload, path)
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != broken {
		t.Fatalf("the check changed config.toml: %q (%v)", after, err)
	}
	if entries, _ := os.ReadDir(dataDir); len(entries) != 0 {
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".lock") {
				t.Errorf("the check wrote %s into the data dir", entry.Name())
			}
		}
	}

	if err := os.WriteFile(path, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	connectorFlagJSON = false
	if _, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", "codex"); code != 0 {
		t.Fatalf("usable config: exit = %d, stderr=%q", code, stderr)
	}
	if _, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", "no-such-agent"); code != 2 {
		t.Fatalf("unknown connector: exit = %d, want 2 (stderr=%q)", code, stderr)
	}
}
