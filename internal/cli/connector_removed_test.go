// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// until 1.1: native Setup and uninstall tear down a removed connector with an
// explicit config home; the teardown-only connector reads it from
// SetupOpts.ConfigHome.
func TestConnectorTeardownRemovedOmnigentHonoursConfigHome(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	configHome := filepath.Join(testenv.PrivateTempDir(t), ".omnigent")
	if err := os.MkdirAll(configHome, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configHome, "config.yaml")
	body := "policy_modules:\n  - corp_policy\n  - defenseclaw_omnigent_policy\n" +
		"policies:\n  defenseclaw_guardrail:\n    handler: defenseclaw_omnigent_policy.defenseclaw_policy\n"
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	defer withConnectorState(t, dataDir, "codex")()

	_, stderr, code := runConnectorCmd(t, "teardown", "--connector", "omnigent", "--config-home", configHome, "--json")
	if code != 0 || strings.Contains(stderr, "unsupported") || strings.Contains(stderr, "unknown connector") {
		t.Fatalf("teardown exit=%d stderr=%s", code, stderr)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "defenseclaw") || !strings.Contains(string(data), "corp_policy") {
		t.Fatalf("config.yaml after teardown = %s", data)
	}
	if _, stderr, code := runConnectorCmd(t, "verify", "--connector", "omnigent", "--config-home", configHome); code != 0 {
		t.Fatalf("verify exit=%d stderr=%s", code, stderr)
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
