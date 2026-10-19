// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0252: `config validate <file>` is read-only and names the profile.
func TestConfigValidateCommandReportsTheProfile(t *testing.T) {
	path, dir := writeSandboxProfileConfig(t, "", "        allowed: false\n        required_for: [claudecode]\n")
	out := &strings.Builder{}
	configValidateCmd.SetOut(out)
	t.Cleanup(func() { configValidateCmd.SetOut(nil); configValidateJSON, configValidateDataDir = false, "" })
	configValidateDataDir = dir
	err := configValidateCmd.RunE(configValidateCmd, []string{path})
	if err == nil || !strings.Contains(err.Error(), `guardrail.profiles["contractors"]`) ||
		!strings.Contains(err.Error(), "allowed: false contradicts required_for") {
		t.Fatalf("config validate error = %v", err)
	}

	good, goodDir := writeSandboxProfileConfig(t, "", "        required_for: [claudecode]\n")
	configValidateDataDir = goodDir
	out.Reset()
	if err := configValidateCmd.RunE(configValidateCmd, []string{good}); err != nil {
		t.Fatalf("config validate refused a valid config: %v", err)
	}
	if !strings.Contains(out.String(), "valid (config_version 9)") {
		t.Fatalf("config validate output = %q", out.String())
	}
	configValidateJSON = true
	out.Reset()
	if err := configValidateCmd.RunE(configValidateCmd, []string{good}); err != nil {
		t.Fatal(err)
	}
	var wire configV8WireResponse
	if err := json.Unmarshal([]byte(out.String()), &wire); err != nil || wire.Valid == nil || !*wire.Valid {
		t.Fatalf("config validate --json = %q (%v)", out.String(), err)
	}
}

// rel-1-0-3 GAP-0091: on a managed computer outside Secure Client, config
// validate named the ignored fail-open settings without the fail_open_ignored
// code that ensure, status and verify print, in its text and its JSON.
func TestConfigValidateCodesIgnoredManagedFailOpenSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	source := fmt.Sprintf("config_version: 9\ndata_dir: %s\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n"+
		"guardrail:\n  mode: observe\n  hook_fail_mode: open\n  connectors:\n    hermes:\n      hook_fail_mode: open\n", dir)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	out := &strings.Builder{}
	configValidateCmd.SetOut(out)
	t.Cleanup(func() { configValidateCmd.SetOut(nil); configValidateJSON, configValidateDataDir = false, "" })
	configValidateDataDir = dir
	want := []string{
		"fail_open_ignored: guardrail.hook_fail_mode: open is ignored on this managed computer",
		"fail_open_ignored: guardrail.connectors.hermes.hook_fail_mode: open is ignored on this managed computer",
	}
	if err := configValidateCmd.RunE(configValidateCmd, []string{path}); err != nil {
		t.Fatalf("config validate refused the managed config: %v", err)
	}
	for _, line := range want {
		if !strings.Contains(out.String(), "warning: "+line) {
			t.Fatalf("config validate text = %q, want a line %q", out.String(), "warning: "+line)
		}
	}
	configValidateJSON = true
	out.Reset()
	if err := configValidateCmd.RunE(configValidateCmd, []string{path}); err != nil {
		t.Fatal(err)
	}
	var wire configV8WireResponse
	if err := json.Unmarshal([]byte(out.String()), &wire); err != nil || wire.Valid == nil || !*wire.Valid {
		t.Fatalf("config validate --json = %q (%v)", out.String(), err)
	}
	var coded []string
	for _, warning := range wire.Warnings {
		if strings.HasPrefix(warning, "fail_open_ignored: ") {
			coded = append(coded, warning)
		}
	}
	if len(coded) != len(want) {
		t.Fatalf("config validate --json warnings = %q, want %d fail_open_ignored warnings", wire.Warnings, len(want))
	}
	for i, line := range want {
		if !strings.HasPrefix(coded[i], line) {
			t.Fatalf("config validate --json warning %d = %q, want prefix %q", i, coded[i], line)
		}
	}
}
