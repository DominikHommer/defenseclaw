// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import "testing"

// A plugin cannot report its own absence. The process scan must name the
// supported launches that bypass plugin loading, including the equivalent
// environment form and the other per-user plugin connector.
func TestPluginLaunchCoverage(t *testing.T) {
	const home = "/home/alice"
	for _, tc := range []struct {
		name, connector string
		argv            []string
		env             map[string]string
		envKnown        bool
		want            string
	}{
		{"OpenCode pure flag", "opencode", []string{"opencode", "--pure"}, nil, false, "opencode_pure"},
		{"OpenCode pure subcommand", "opencode", []string{"opencode", "run", "--pure=true", "hello"}, nil, false, "opencode_pure"},
		{"OpenCode pure environment", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_PURE": "1"}, true, "opencode_pure"},
		{"OpenCode moved managed config", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_TEST_MANAGED_CONFIG_DIR": "/tmp/empty"}, true, "opencode_managed_config_relocated"},
		{"OpenCode moved user config", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_CONFIG_DIR": "/tmp/empty"}, true, "opencode_user_config_relocated"},
		{"OpenCode moved XDG config", "opencode", []string{"opencode"}, map[string]string{"XDG_CONFIG_HOME": "/tmp/empty"}, true, "opencode_user_config_relocated"},
		{"OpenCode environment unreadable", "opencode", []string{"opencode"}, nil, false, "launch_environment_unverified"},
		{"OpenCode arguments unreadable", "opencode", nil, nil, false, "launch_environment_unverified"},
		{"OpenCode normal", "opencode", []string{"opencode", "run", "hello"}, map[string]string{}, true, ""},
		{"OpenCode prompt text", "opencode", []string{"opencode", "run", "please test --pure"}, map[string]string{}, true, ""},
		{"OpenCode false flag", "opencode", []string{"opencode", "--pure=false"}, map[string]string{}, true, ""},
		{"Amp relocated XDG", "amp", []string{"amp"}, map[string]string{"XDG_CONFIG_HOME": "/tmp/amp"}, true, "amp_plugin_config_relocated"},
		{"Amp relocated home", "amp", []string{"amp"}, map[string]string{"HOME": "/tmp/home"}, true, "amp_plugin_config_relocated"},
		{"Amp normal", "amp", []string{"amp"}, map[string]string{"HOME": home, "XDG_CONFIG_HOME": home + "/.config"}, true, ""},
		{"Amp environment unreadable", "amp", []string{"amp"}, nil, false, "launch_environment_unverified"},
		{"Amp home and config unset", "amp", []string{"amp"}, map[string]string{}, true, "launch_environment_unverified"},
		{"Devin config flag", "devin", []string{"devin", "--config", "/tmp/other.json"}, nil, false, "devin_config_override"},
		{"Devin config equals", "devin", []string{"devin", "--config=/tmp/other.json"}, nil, false, "devin_config_override"},
		{"Devin moved home", "devin", []string{"devin"}, map[string]string{"HOME": "/tmp/other"}, true, "user_config_relocated"},
		{"Devin normal", "devin", []string{"devin"}, map[string]string{"HOME": home}, true, ""},
		{"Hermes safe mode", "hermes", []string{"hermes", "--safe-mode"}, nil, false, "hermes_safe_mode"},
		{"Hermes safe abbreviation", "hermes", []string{"hermes", "--sa"}, nil, false, "hermes_safe_mode"},
		{"Hermes safe environment", "hermes", []string{"hermes"}, map[string]string{"HERMES_SAFE_MODE": "1"}, true, "hermes_safe_mode"},
		{"Hermes moved managed dir", "hermes", []string{"hermes"}, map[string]string{"HERMES_MANAGED_DIR": "/tmp/other"}, true, "hermes_config_relocated"},
		{"Hermes ignore user config keeps hooks", "hermes", []string{"hermes", "--ignore-user-config"}, map[string]string{"HOME": home}, true, ""},
		{"Antigravity moved home", "antigravity", []string{"agy"}, map[string]string{"HOME": "/tmp/other"}, true, "user_config_relocated"},
		{"Kiro alternate agent", "kiro", []string{"kiro-cli", "--agent", "mine"}, nil, false, "kiro_alternate_agent"},
		{"Kiro alternate agent equals", "kiro", []string{"kiro-cli", "--agent=mine"}, nil, false, "kiro_alternate_agent"},
		{"Kiro managed agent", "kiro", []string{"kiro-cli", "--agent=defenseclaw"}, map[string]string{}, true, ""},
		{"Kiro cloud", "kiro", []string{"kiro-cli", "--cloud"}, nil, false, "kiro_cloud_session"},
		{"Kiro moved agents", "kiro", []string{"kiro-cli"}, map[string]string{"KIRO_AGENT_CONFIG_DIR": "/tmp/agents"}, true, "kiro_hook_config_relocated"},
		{"Kiro moved test agents", "kiro", []string{"kiro-cli"}, map[string]string{"KIRO_TEST_AGENTS_DIR": "/tmp/agents"}, true, "kiro_hook_config_relocated"},
		{"Other connector", "codex", []string{"codex", "--pure"}, nil, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := PluginLaunchCoverage(tc.connector, tc.argv, tc.env, tc.envKnown, home); got != tc.want {
				t.Fatalf("coverage = %q, want %q", got, tc.want)
			}
		})
	}
}
