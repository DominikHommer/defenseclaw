// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// The native hook and the installers' refresh read a config.yaml document's
// explicit fail modes without loading it (a 0.8.x one before 'defenseclaw
// migrate'). A Cursor open the operator wrote is kept outside action mode,
// whose Cursor hooks are closed; before r104 W3 G3-upg every Cursor value was
// ignored, so a 0.8.x explicit open was closed during the upgrade.
func TestConfiguredHookFailModeInDocumentReadsCursor(t *testing.T) {
	for _, test := range []struct{ name, doc, want string }{
		{"0.8.x cursor open in observe", "config_version: 7\nguardrail:\n  mode: observe\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", "open"},
		{"global open, mode unset", "guardrail:\n  hook_fail_mode: open\n", "open"},
		{"cursor closed", "guardrail:\n  mode: observe\n  hook_fail_mode: open\n  connectors:\n    cursor:\n      hook_fail_mode: closed\n", "closed"},
		{"cursor open under action", "guardrail:\n  mode: action\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", "closed"},
		{"cursor action override", "guardrail:\n  mode: observe\n  hook_fail_mode: open\n  connectors:\n    cursor:\n      mode: action\n", "closed"},
		{"legacy enforce", "guardrail:\n  mode: enforce\n  hook_fail_mode: open\n", "closed"},
		{"unset", "guardrail:\n  mode: observe\n", ""},
		{"automatic protection decides", "guardrail:\n  hook_fail_mode: open\napplication_protection:\n  enabled: true\n", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ConfiguredHookFailModeInDocument([]byte(test.doc), "cursor"); got != test.want {
				t.Fatalf("cursor fail mode = %q, want %q", got, test.want)
			}
		})
	}
	// Another connector's open does not depend on the guardrail mode.
	if got := ConfiguredHookFailModeInDocument([]byte("guardrail:\n  mode: action\n  hook_fail_mode: open\n"), "codex"); got != "open" {
		t.Fatalf("codex fail mode under action = %q, want open", got)
	}
}
