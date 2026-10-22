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
