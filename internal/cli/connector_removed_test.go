// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const (
	removedOmnigentOperatorConfig = "policy_modules:\n  - corp_policy\n"
	removedOmnigentPatchedConfig  = "policy_modules:\n  - corp_policy\n  - defenseclaw_omnigent_policy\n" +
		"policies:\n  defenseclaw_guardrail:\n    handler: defenseclaw_omnigent_policy.defenseclaw_policy\n"
)

// writeRemovedSetupRecord writes config.yaml as an older OmniGent setup left
// it, with the backup record of the file it found.
func writeRemovedSetupRecord(t *testing.T, dataDir, path string) {
	t.Helper()
	sum := func(data string) string {
		digest := sha256.Sum256([]byte(data))
		return hex.EncodeToString(digest[:])
	}
	record, err := json.Marshal(map[string]any{
		"version": 1, "connector": "omnigent", "logical_name": "config", "path": path,
		"existed": true, "mode": 0o600, "pristine_sha256": sum(removedOmnigentOperatorConfig),
		"pristine_bytes": []byte(removedOmnigentOperatorConfig), "post_sha256": sum(removedOmnigentPatchedConfig),
		"captured_at": "2026-10-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	for file, body := range map[string]string{
		filepath.Join(dataDir, "connector_backups", "omnigent", "config.json"): string(record),
		path: removedOmnigentPatchedConfig,
	} {
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// until 1.1: native Setup and uninstall tear down a removed connector with an
// explicit config home; the teardown-only connector reads it from
// SetupOpts.ConfigHome. A config.yaml exactly as setup left it is put back; an
// edited one is left alone with the manual steps, and teardown and verify
// still succeed so uninstall and Setup go on.
func TestConnectorTeardownRemovedOmnigentHonoursConfigHome(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edited bool
	}{{"unchanged since setup", false}, {"edited since setup", true}} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			configHome := filepath.Join(testenv.PrivateTempDir(t), ".omnigent")
			configPath := filepath.Join(configHome, "config.yaml")
			writeRemovedSetupRecord(t, dataDir, configPath)
			want := removedOmnigentOperatorConfig
			if tc.edited {
				want = removedOmnigentPatchedConfig + "model: local\n"
				if err := os.WriteFile(configPath, []byte(want), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			defer withConnectorState(t, dataDir, "codex")()

			_, stderr, code := runConnectorCmd(t, "teardown", "--connector", "omnigent", "--config-home", configHome, "--json")
			if code != 0 || strings.Contains(stderr, "unsupported") || strings.Contains(stderr, "unknown connector") {
				t.Fatalf("teardown exit=%d stderr=%s", code, stderr)
			}
			record, err := os.ReadFile(filepath.Join(dataDir, "removed_connector_cleanup", "omnigent.json"))
			if tc.edited != (err == nil && strings.Contains(string(record), configPath)) {
				t.Fatalf("manual cleanup record = %s, %v; want one naming config.yaml only when it was edited", record, err)
			}
			data, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != want {
				t.Fatalf("config.yaml after teardown = %q, want %q", data, want)
			}
			if _, stderr, code := runConnectorCmd(t, "verify", "--connector", "omnigent", "--config-home", configHome); code != 0 {
				t.Fatalf("verify exit=%d stderr=%s", code, stderr)
			}
		})
	}
}

// A removed connector can be torn down but never reconciled, and the
// selected refresh stays limited to the connectors native Setup refreshes.
func TestConnectorReconcileRefusesUnsupportedConnectors(t *testing.T) {
	for _, name := range []string{"omnigent", "openhands", "kiro"} {
		t.Run(name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			defer withConnectorState(t, dataDir, "codex")()
			_, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", name, "--json")
			if !strings.Contains(stderr, "unknown connector") && !strings.Contains(stderr, "selected refresh is supported only") {
				t.Fatalf("reconcile %s stderr = %q, want a refusal", name, stderr)
			}
		})
	}
}
