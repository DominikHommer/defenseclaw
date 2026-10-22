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

// useConfigValidateLayout points config validate at a Linux standalone
// layout under dir; managedHost publishes its runtime descriptor.
func useConfigValidateLayout(t *testing.T, dir string, managedHost bool) managed.StandaloneLayout {
	t.Helper()
	layout, err := managed.StandaloneLayoutFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	layout.ConfigPath = filepath.Join(dir, "etc", "config.yaml")
	layout.DescriptorPath = filepath.Join(dir, "etc", "managed-runtime.json")
	layout.DataDir = filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if managedHost {
		if err := os.WriteFile(layout.DescriptorPath, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previous := configValidateLayout
	configValidateLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	t.Cleanup(func() {
		configValidateLayout = previous
		configValidateCmd.SetOut(nil)
		configValidateJSON, configValidateDataDir, configValidatePath = false, "", ""
	})
	return layout
}

// GAP-0601: validate refuses what ensure refuses a managed standalone config
// on, in a candidate and in the installed config alike: a bind beyond
// loopback or another port on any computer, and on a managed computer also
// a data_dir outside its layout.
func TestConfigValidateRefusesManagedLayoutValues(t *testing.T) {
	const head = "config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n"
	dir := t.TempDir()
	for _, tc := range []struct {
		name, body, want string
		managedHost      bool
	}{
		{"bind beyond loopback", "gateway:\n  api_bind: 0.0.0.0\n", `gateway.api_bind "0.0.0.0" must be 127.0.0.1`, false},
		{"another port", "gateway:\n  api_port: 18971\n", "gateway.api_port 18971 must be 18970", false},
		{"another data_dir", "data_dir: " + filepath.Join(dir, "elsewhere") + "\n", "must be " + filepath.Join(dir, "managed", "state"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := useConfigValidateLayout(t, filepath.Join(dir, "managed"), tc.managedHost)
			configValidateDataDir = layout.DataDir
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(head+tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, installed := range []string{filepath.Join(dir, "installed.yaml"), path} {
				t.Setenv(managed.ConfigPathEnv, installed)
				configValidateCmd.SetOut(&strings.Builder{})
				if err := configValidateCmd.RunE(configValidateCmd, []string{path}); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("config validate (installed %s) = %v, want a refusal naming %s", installed, err, tc.want)
				}
			}
		})
	}
	useConfigValidateLayout(t, filepath.Join(dir, "managed"), true)
	path := filepath.Join(dir, "loopback.yaml")
	if err := os.WriteFile(path, []byte(head+"gateway:\n  api_bind: 127.0.0.1\n  api_port: 18970\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configValidateCmd.SetOut(&strings.Builder{})
	if err := configValidateCmd.RunE(configValidateCmd, []string{path}); err != nil {
		t.Fatalf("the managed layout's own values refused: %v", err)
	}
}

// GAP-0602: with no file, validate on a standalone managed computer reads
// the installed managed config, not the per-user one root has none of.
func TestConfigValidateDefaultsToTheManagedInstalledConfig(t *testing.T) {
	dir := t.TempDir()
	layout := useConfigValidateLayout(t, dir, true)
	if err := os.WriteFile(layout.ConfigPath, []byte("config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.ConfigPathEnv, "")
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(dir, "per-user"))
	out := &strings.Builder{}
	configValidateCmd.SetOut(out)
	if err := configValidateCmd.RunE(configValidateCmd, nil); err != nil {
		t.Fatalf("config validate with no file on a managed computer: %v", err)
	}
	if !strings.Contains(out.String(), layout.ConfigPath+": valid") {
		t.Fatalf("config validate output = %q, want %s validated", out.String(), layout.ConfigPath)
	}
}
