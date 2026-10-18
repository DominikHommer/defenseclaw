// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const managedLiteralSentinel = "example-sensitive-value"

// GAP-0138: `config validate` applies the managed candidate rule that
// `enterprise linux ensure --config` applies, so a file it calls valid is
// one ensure accepts. The installed config keeps loading for the upgrade
// path and gets the status/verify advisory instead.
func TestConfigValidateRefusesManagedLiteralCandidates(t *testing.T) {
	t.Cleanup(func() { configValidateCmd.SetOut(nil); configValidateJSON, configValidateDataDir = false, "" })
	const head = "config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n"
	for _, tc := range []struct {
		name, body, path string
	}{
		{"destination header", "observability:\n  destinations:\n  - name: archive\n    kind: http_jsonl\n    enabled: false\n" +
			"    endpoint: https://example.test/events\n    headers:\n      Authorization: " + managedLiteralSentinel + "\n",
			"observability.destinations[0].headers"},
		{"provider header", "llm:\n  extra_headers:\n    x-api-key: " + managedLiteralSentinel + "\n", "llm.extra_headers"},
		{"judge header", "guardrail:\n  judge:\n    llm:\n      extra_headers:\n        Authorization: " + managedLiteralSentinel + "\n",
			"guardrail.judge.llm.extra_headers"},
		{"legacy inspect key", "inspect_llm:\n  api_key: " + managedLiteralSentinel + "\n", "inspect_llm.api_key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv(managed.ConfigPathEnv, filepath.Join(dir, "installed", "config.yaml"))
			path := filepath.Join(dir, "candidate.yaml")
			if err := os.WriteFile(path, []byte(head+tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			configValidateDataDir = dir
			out := &strings.Builder{}
			configValidateCmd.SetOut(out)
			err := configValidateCmd.RunE(configValidateCmd, []string{path})
			if err == nil || !strings.Contains(err.Error(), tc.path) || !strings.Contains(err.Error(), "{credential: NAME}") ||
				strings.Contains(err.Error(), managedLiteralSentinel) || strings.Contains(out.String(), managedLiteralSentinel) {
				t.Fatalf("config validate = %v (out %q), want a redacted refusal at %s", err, out.String(), tc.path)
			}

			// The same bytes as the installed config: valid, with the advisory.
			t.Setenv(managed.ConfigPathEnv, path)
			out.Reset()
			if err := configValidateCmd.RunE(configValidateCmd, []string{path}); err != nil {
				t.Fatalf("installed config refused: %v", err)
			}
			if !strings.Contains(out.String(), "managed_literal_credentials") || !strings.Contains(out.String(), tc.path) ||
				strings.Contains(out.String(), managedLiteralSentinel) {
				t.Fatalf("installed config output = %q, want the advisory at %s", out.String(), tc.path)
			}
		})
	}

	// A benign routing header and a generic webhook remain valid candidates.
	dir := t.TempDir()
	t.Setenv(managed.ConfigPathEnv, filepath.Join(dir, "installed", "config.yaml"))
	path := filepath.Join(dir, "candidate.yaml")
	if err := os.WriteFile(path, []byte(head+"llm:\n  extra_headers:\n    X-Route: region-west\n"+
		"webhooks:\n  - url: https://example.test/hook\n    type: generic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configValidateDataDir = dir
	configValidateCmd.SetOut(&strings.Builder{})
	if err := configValidateCmd.RunE(configValidateCmd, []string{path}); err != nil {
		t.Fatalf("benign managed candidate refused: %v", err)
	}
}
