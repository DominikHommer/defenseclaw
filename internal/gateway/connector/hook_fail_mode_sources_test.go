// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func readHookConfigSidecarForTest(t *testing.T, hookDir string) hookConfigSidecar {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(hookDir, hookConfigSidecarName))
	if err != nil {
		t.Fatal(err)
	}
	var state hookConfigSidecar
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

// Each connector entry this release writes records that its mode was
// resolved from the config; a peer entry an earlier release wrote keeps no
// source, so the native hook does not trust its open. A managed sidecar
// carries no sources (its readers reject unknown fields), and a teardown
// removes the connector's source with its mode.
func TestHookConfigSidecarRecordsTheSourceOfEachMode(t *testing.T) {
	hookDir := t.TempDir()
	legacy := `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"claudecode":"open","codex":"open"}}` + "\n"
	if err := os.WriteFile(filepath.Join(hookDir, hookConfigSidecarName), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeHookConfigSidecar(hookDir, "127.0.0.1:18970", "codex", "closed", false); err != nil {
		t.Fatal(err)
	}
	state := readHookConfigSidecarForTest(t, hookDir)
	if !reflect.DeepEqual(state.FailModes, map[string]string{"claudecode": "open", "codex": "closed"}) ||
		!reflect.DeepEqual(state.FailModeSources, map[string]string{"codex": HookFailModeSourceConfig}) {
		t.Fatalf("sidecar after a codex render: %+v", state)
	}
	if err := writeHookConfigSidecar(hookDir, "127.0.0.1:18970", "claudecode", "open", false); err != nil {
		t.Fatal(err)
	}
	if state := readHookConfigSidecarForTest(t, hookDir); state.FailModeSources["claudecode"] != HookFailModeSourceConfig ||
		state.FailModeSources["codex"] != HookFailModeSourceConfig {
		t.Fatalf("peer source not carried: %+v", state)
	}
	if err := clearHookConfigSidecarEntry(hookDir, "codex"); err != nil {
		t.Fatal(err)
	}
	if state := readHookConfigSidecarForTest(t, hookDir); state.FailModes["codex"] != "" || state.FailModeSources["codex"] != "" {
		t.Fatalf("teardown left the codex entry: %+v", state)
	}

	if runtime.GOOS == "windows" {
		// The Windows managed writer publishes with the guardian's DACLs.
		return
	}
	managedDir := t.TempDir()
	if err := writeHookConfigSidecarUsing(managedDir, "127.0.0.1:18970", "codex", "closed", true, atomicWriteFile); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(managedDir, hookConfigSidecarName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "fail_mode_sources") {
		t.Fatalf("managed sidecar carries sources: %s", body)
	}
	var strict hookConfigSidecar
	if err := decodeManagedHookConfigSidecar(body, &strict); err != nil {
		t.Fatalf("managed sidecar does not decode strictly: %v", err)
	}
}

// The installers' pre-swap render: every entry of an earlier release's
// sidecar takes the mode this release renders from the config, with its
// source, and both the JSON and the flat shell records agree. An entry the
// resolver cannot name is left alone; a managed or missing sidecar is not
// touched.
func TestRefreshHookFailModesRendersAnEarlierReleasesSidecar(t *testing.T) {
	hookDir := t.TempDir()
	legacy := `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"claudecode":"open","codex":"open","retired":"open"}}` + "\n"
	if err := os.WriteFile(filepath.Join(hookDir, hookConfigSidecarName), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	modes := map[string]string{"claudecode": "closed", "codex": "open"}
	refreshed, err := RefreshHookFailModes(hookDir, func(name string) string { return modes[name] })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(refreshed, []string{"claudecode", "codex"}) {
		t.Fatalf("refreshed %v", refreshed)
	}
	state := readHookConfigSidecarForTest(t, hookDir)
	if !reflect.DeepEqual(state.FailModes, map[string]string{"claudecode": "closed", "codex": "open", "retired": "open"}) ||
		!reflect.DeepEqual(state.FailModeSources, map[string]string{"claudecode": HookFailModeSourceConfig, "codex": HookFailModeSourceConfig}) ||
		state.GatewayAddr != "127.0.0.1:18970" {
		t.Fatalf("sidecar after refresh: %+v", state)
	}
	for name, want := range modes {
		flat, err := os.ReadFile(filepath.Join(hookDir, hookConfigSidecarName+"."+name))
		if err != nil || legacyHookConfigValue(flat, "DEFENSECLAW_FAIL_MODE") != want {
			t.Fatalf("%s flat record %q (%v), want %s", name, flat, err, want)
		}
	}

	if refreshed, err := RefreshHookFailModes(t.TempDir(), func(string) string { return "closed" }); err != nil || refreshed != nil {
		t.Fatalf("missing sidecar: %v %v", refreshed, err)
	}
	managedDir := t.TempDir()
	managedBody := `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"},"managed_enterprise":true}` + "\n"
	if err := os.WriteFile(filepath.Join(managedDir, hookConfigSidecarName), []byte(managedBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if refreshed, err := RefreshHookFailModes(managedDir, func(string) string { return "closed" }); err != nil || refreshed != nil {
		t.Fatalf("managed sidecar: %v %v", refreshed, err)
	}
	if body, _ := os.ReadFile(filepath.Join(managedDir, hookConfigSidecarName)); string(body) != managedBody {
		t.Fatalf("managed sidecar rewritten: %s", body)
	}
}
