// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type refreshFailModesResult struct {
	Config    string   `json:"config"`
	Refreshed []string `json:"refreshed"`
}

// runRefreshFailModesForTest runs the installers' pre-swap refresh against
// home, as the staged gateway does.
func runRefreshFailModesForTest(t *testing.T, home string) refreshFailModesResult {
	t.Helper()
	previousCfg, previousDir, previousJSON := cfg, connectorFlagDataDir, connectorFlagJSON
	t.Cleanup(func() { cfg, connectorFlagDataDir, connectorFlagJSON = previousCfg, previousDir, previousJSON })
	connectorFlagDataDir, connectorFlagJSON = home, true
	var out bytes.Buffer
	connectorRefreshFailModesCmd.SetOut(&out)
	t.Cleanup(func() { connectorRefreshFailModesCmd.SetOut(nil) })
	if err := runConnectorRefreshFailModes(connectorRefreshFailModesCmd, nil); err != nil {
		t.Fatal(err)
	}
	var result refreshFailModesResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("refresh output %q: %v", out.String(), err)
	}
	return result
}

// oldHookFailMode is the mode a 0.8.10-1.0.3 native hook reads for connector
// from hooks/.hookcfg: the fail_modes entry, whatever its source.
func oldHookFailMode(t *testing.T, home, connector string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, "hooks", ".hookcfg"))
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		FailModes map[string]string `json:"fail_modes"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state.FailModes[connector]
}

func isolateHookEnvForTest(t *testing.T, home string) {
	t.Helper()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", "")
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "")
}

// A Windows 0.8.x upgrade: the 0.8.x config (config_version 7) cannot load
// before 'defenseclaw migrate', and the 0.8.10 sidecar holds the open 0.8.x
// resolved for an unset mode under observe. The refresh reads the config's
// explicit fail modes and closes it, so the old hook and the new one both
// fail closed while the gateway is down for the swap.
func TestRefreshFailModesClosesA08xSidecarOpenNobodySet(t *testing.T) {
	home := t.TempDir()
	isolateHookEnvForTest(t, home)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("config_version: 7\nguardrail:\n  mode: observe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open","claudecode":"open"}}`)
	if got := oldHookFailMode(t, home, "codex"); got != "open" {
		t.Fatalf("precondition: the old hook reads %q", got)
	}

	result := runRefreshFailModesForTest(t, home)
	if result.Config != "document" || !reflect.DeepEqual(result.Refreshed, []string{"claudecode", "codex"}) {
		t.Fatalf("refresh %+v", result)
	}
	for _, name := range []string{"codex", "claudecode"} {
		if got := oldHookFailMode(t, home, name); got != "closed" {
			t.Fatalf("the old %s hook reads %q, want closed", name, got)
		}
		if got := buildHookOptions(name, "PreToolUse", "", "").FailMode; got != "closed" {
			t.Fatalf("the new %s hook fails %q, want closed", name, got)
		}
	}
}

// An operator open in a 0.8.x config outside the data directory
// (DEFENSECLAW_CONFIG): the new hook never reads that path, so without the
// refresh it blocks during the upgrade outage. The refresh carries the open
// into the sidecar with its config source, and the new hook follows it with
// no DEFENSECLAW_CONFIG in its environment.
func TestRefreshFailModesCarriesAnExternalConfigsOpen(t *testing.T) {
	home := t.TempDir()
	isolateHookEnvForTest(t, home)
	external := filepath.Join(t.TempDir(), "defenseclaw.yaml")
	if err := os.WriteFile(external, []byte("config_version: 7\nguardrail:\n  mode: observe\n  hook_fail_mode: open\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"}}`)
	if got := buildHookOptions("codex", "PreToolUse", "", "").FailMode; got != "closed" {
		t.Fatalf("precondition: the new hook fails %q before the refresh", got)
	}

	t.Setenv("DEFENSECLAW_CONFIG", external)
	if result := runRefreshFailModesForTest(t, home); result.Config != "document" || !reflect.DeepEqual(result.Refreshed, []string{"codex"}) {
		t.Fatalf("refresh %+v", result)
	}
	t.Setenv("DEFENSECLAW_CONFIG", "")
	if got := buildHookOptions("codex", "PreToolUse", "", "").FailMode; got != "open" {
		t.Fatalf("the new hook fails %q, want the operator's open", got)
	}
}

// A loaded config: an earlier render recorded Copilot's unset mode as open
// (lowered because its vendor hook surface cannot fail closed) without a
// source. No operator chose it, so the refresh writes the closed outage mode
// and a gateway-down native call is blocked. An explicit connector open stays
// open.
func TestRefreshFailModesDoesNotTreatACapabilityOpenAsTheConfigs(t *testing.T) {
	for _, test := range []struct {
		name, config, want string
	}{
		{name: "unset", config: "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n", want: "closed"},
		{name: "operator open", config: "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n  connectors:\n    copilot:\n      hook_fail_mode: open\n", want: "open"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			isolateHookEnvForTest(t, home)
			if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(test.config), 0o600); err != nil {
				t.Fatal(err)
			}
			// What the earlier render recorded for Copilot: open, no source.
			writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"copilot":"open"}}`)
			if got := buildHookOptions("copilot", "preToolUse", "", "").FailMode; got != test.want {
				t.Fatalf("before the refresh the native hook fails %q, want %q", got, test.want)
			}
			if result := runRefreshFailModesForTest(t, home); result.Config != "loaded" || !reflect.DeepEqual(result.Refreshed, []string{"copilot"}) {
				t.Fatalf("refresh %+v", result)
			}
			if got := oldHookFailMode(t, home, "copilot"); got != test.want {
				t.Fatalf("refreshed copilot mode %q, want %q", got, test.want)
			}
			if got := buildHookOptions("copilot", "preToolUse", "", "").FailMode; got != test.want {
				t.Fatalf("the native hook fails %q, want %q", got, test.want)
			}
		})
	}
}

// Cursor in observe: its resolved mode (open) follows the guardrail mode, so
// a 1.0.x refresh that wrote it (with its config source) let the old and the
// new hooks allow calls while the gateway was down. The refresh writes open
// only for an explicit open, from a loaded config or from a 0.8.x document
// alike, and never under action mode.
func TestRefreshFailModesClosesACursorOpenNobodyChose(t *testing.T) {
	const v9 = "config_version: 9\nobservability: {}\nguardrail:\n"
	const v7 = "config_version: 7\nguardrail:\n"
	for _, test := range []struct {
		name, config, read, want string
	}{
		{"1.0.x observe, unset", v9 + "  mode: observe\n", "loaded", "closed"},
		{"1.0.x observe, cursor open", v9 + "  mode: observe\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", "loaded", "open"},
		{"1.0.x action, cursor open", v9 + "  mode: action\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", "loaded", "closed"},
		{"0.8.x observe, unset", v7 + "  mode: observe\n", "document", "closed"},
		{"0.8.x observe, cursor open", v7 + "  mode: observe\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", "document", "open"},
		{"0.8.x action, cursor open", v7 + "  mode: action\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", "document", "closed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			isolateHookEnvForTest(t, home)
			if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(test.config), 0o600); err != nil {
				t.Fatal(err)
			}
			// The 0.8.10 to 1.0.3 render for an observe Cursor.
			writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"cursor":"open"}}`)
			if result := runRefreshFailModesForTest(t, home); result.Config != test.read || !reflect.DeepEqual(result.Refreshed, []string{"cursor"}) {
				t.Fatalf("refresh %+v", result)
			}
			if got := oldHookFailMode(t, home, "cursor"); got != test.want {
				t.Fatalf("the old cursor hook reads %q, want %q", got, test.want)
			}
			if got := buildHookOptions("cursor", "beforeShellExecution", "", "").FailMode; got != test.want {
				t.Fatalf("the new cursor hook fails %q, want %q", got, test.want)
			}
		})
	}
}

// A managed install's hooks take their mode from protected state: the
// refresh leaves its sidecar alone, loaded or not.
func TestRefreshFailModesLeavesAManagedInstallAlone(t *testing.T) {
	home := t.TempDir()
	isolateHookEnvForTest(t, home)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("config_version: 7\ndeployment_mode: managed_enterprise\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const body = `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"}}`
	writeHookSidecarForTest(t, home, body)
	if result := runRefreshFailModesForTest(t, home); len(result.Refreshed) != 0 {
		t.Fatalf("refresh %+v", result)
	}
	if got, _ := os.ReadFile(filepath.Join(home, "hooks", ".hookcfg")); string(got) != body {
		t.Fatalf("managed sidecar rewritten: %s", got)
	}
}
