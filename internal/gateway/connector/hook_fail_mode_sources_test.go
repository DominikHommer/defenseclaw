// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"os/exec"
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

func readFlatHookRecordForTest(t *testing.T, hookDir, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(hookDir, hookConfigSidecarName+"."+name))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// Each connector entry this release writes records that its mode was
// resolved from the config, in the JSON sidecar and in its flat shell record;
// a peer entry an earlier release wrote keeps no source, so the native hook
// and the shared shell readers do not trust its open. A managed sidecar
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
	if got := readFlatHookRecordForTest(t, hookDir, "codex"); got != "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=closed\nFAIL_MODE_SOURCE=config\n" {
		t.Fatalf("codex flat record %q", got)
	}
	if err := writeHookConfigSidecar(hookDir, "127.0.0.1:18970", "claudecode", "open", false); err != nil {
		t.Fatal(err)
	}
	if state := readHookConfigSidecarForTest(t, hookDir); state.FailModeSources["claudecode"] != HookFailModeSourceConfig ||
		state.FailModeSources["codex"] != HookFailModeSourceConfig {
		t.Fatalf("peer source not carried: %+v", state)
	}
	// A mode the config did not choose drops the entry's source.
	if err := writeHookConfigSidecarUsing(hookDir, "127.0.0.1:18970", "claudecode", "open", "", false, atomicWriteFile); err != nil {
		t.Fatal(err)
	}
	if state := readHookConfigSidecarForTest(t, hookDir); state.FailModeSources["claudecode"] != "" ||
		state.FailModeSources["codex"] != HookFailModeSourceConfig {
		t.Fatalf("unsourced write kept a source: %+v", state)
	}
	if got := readFlatHookRecordForTest(t, hookDir, "claudecode"); strings.Contains(got, "SOURCE") {
		t.Fatalf("unsourced flat record %q", got)
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
	if err := writeHookConfigSidecarUsing(managedDir, "127.0.0.1:18970", "codex", "closed", HookFailModeSourceConfig, true, atomicWriteFile); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(managedDir, hookConfigSidecarName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "fail_mode_source") {
		t.Fatalf("managed sidecar carries sources: %s", body)
	}
	if got := readFlatHookRecordForTest(t, managedDir, "codex"); got != "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=closed\n" {
		t.Fatalf("managed flat record %q", got)
	}
	var strict hookConfigSidecar
	if err := decodeManagedHookConfigSidecar(body, &strict); err != nil {
		t.Fatalf("managed sidecar does not decode strictly: %v", err)
	}
}

// A per-user connector whose vendor hook surface cannot fail closed (Copilot)
// renders open for an unset mode (CapableHookFailMode). That open is the
// vendor's limit, not the operator's: the sidecar records it without a
// source, so the native hook fails it closed, and the outage mode the
// installers' refresh writes is closed. An explicit open is the config's.
func TestCapabilityLoweredOpenIsNotRecordedAsTheConfigs(t *testing.T) {
	for _, test := range []struct {
		name, failMode, wantSource, wantOutage string
	}{
		{name: "unset", wantSource: "", wantOutage: "closed"},
		{name: "explicit open", failMode: "open", wantSource: HookFailModeSourceConfig, wantOutage: "open"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir := t.TempDir()
			hookDir := filepath.Join(dataDir, "hooks")
			opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", HookFailMode: test.failMode}
			conn := NewCopilotConnector()
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
				t.Fatal(err)
			}
			state := readHookConfigSidecarForTest(t, hookDir)
			if state.FailModes["copilot"] != "open" || state.FailModeSources["copilot"] != test.wantSource {
				t.Fatalf("copilot sidecar %+v, want open with source %q", state, test.wantSource)
			}
			if got := strings.Contains(readFlatHookRecordForTest(t, hookDir, "copilot"), "FAIL_MODE_SOURCE=config"); got != (test.wantSource != "") {
				t.Fatalf("copilot flat record source = %v, want %v", got, test.wantSource != "")
			}
			if got := OutageHookFailMode(opts, conn); got != test.wantOutage {
				t.Fatalf("outage fail mode %q, want %q", got, test.wantOutage)
			}
		})
	}
}

// The installers' pre-swap refresh: every entry of an earlier release's
// sidecar takes the mode the config chooses, with its source, and both the
// JSON and the flat shell records agree. An entry the resolver cannot name
// is left alone; a managed or missing sidecar is not touched.
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
	if !reflect.DeepEqual(refreshed.Sidecar, []string{"claudecode", "codex"}) || refreshed.Scripts != nil {
		t.Fatalf("refreshed %+v", refreshed)
	}
	state := readHookConfigSidecarForTest(t, hookDir)
	if !reflect.DeepEqual(state.FailModes, map[string]string{"claudecode": "closed", "codex": "open", "retired": "open"}) ||
		!reflect.DeepEqual(state.FailModeSources, map[string]string{"claudecode": HookFailModeSourceConfig, "codex": HookFailModeSourceConfig}) ||
		state.GatewayAddr != "127.0.0.1:18970" {
		t.Fatalf("sidecar after refresh: %+v", state)
	}
	for name, want := range modes {
		flat := readFlatHookRecordForTest(t, hookDir, name)
		if legacyHookConfigValue([]byte(flat), "DEFENSECLAW_FAIL_MODE") != want ||
			legacyHookConfigValue([]byte(flat), "FAIL_MODE_SOURCE") != HookFailModeSourceConfig {
			t.Fatalf("%s flat record %q, want %s from the config", name, flat, want)
		}
	}

	if refreshed, err := RefreshHookFailModes(t.TempDir(), func(string) string { return "closed" }); err != nil ||
		refreshed.Sidecar != nil || refreshed.Scripts != nil {
		t.Fatalf("missing sidecar: %+v %v", refreshed, err)
	}
	managedDir := t.TempDir()
	managedBody := `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"},"managed_enterprise":true}` + "\n"
	if err := os.WriteFile(filepath.Join(managedDir, hookConfigSidecarName), []byte(managedBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if refreshed, err := RefreshHookFailModes(managedDir, func(string) string { return "closed" }); err != nil ||
		refreshed.Sidecar != nil || refreshed.Scripts != nil {
		t.Fatalf("managed sidecar: %+v %v", refreshed, err)
	}
	if body, _ := os.ReadFile(filepath.Join(managedDir, hookConfigSidecarName)); string(body) != managedBody {
		t.Fatalf("managed sidecar rewritten: %s", body)
	}

	corruptDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(corruptDir, hookConfigSidecarName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshHookFailModes(corruptDir, func(string) string { return "closed" }); err == nil ||
		!strings.Contains(err.Error(), hookConfigSidecarName) {
		t.Fatalf("an unreadable sidecar was not refused: %v", err)
	}
}

// What an earlier release left beside the sidecar is refreshed too: the
// KEY=value sidecar of an install older than 0.8.10, a flat shell record with
// no JSON entry, and the open a connector hook script bakes (0.8.10 to 1.0.2
// let the environment open it; 1.0.3 bakes it, and its missing-home check).
// While the gateway is down for the swap, the old hook scripts allow a call
// before the refresh and block it after; an open the config sets stays.
func TestRefreshHookFailModesClosesAnEarlierReleasesHooks(t *testing.T) {
	hookDir := t.TempDir()
	write := func(name, body string, perm os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(hookDir, name), []byte(body), perm); err != nil {
			t.Fatal(err)
		}
	}
	write(hookConfigSidecarName, "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:18970\nDEFENSECLAW_FAIL_MODE=open\n", 0o600)
	write(hookConfigSidecarName+".kiro", "DEFENSECLAW_CONNECTOR=kiro\nDEFENSECLAW_FAIL_MODE=open\n", 0o600)
	// The outage path of each release's per-user connector script, as rendered
	// for an open mode.
	const outage = "if [ \"$FAIL_MODE\" = \"closed\" ]; then echo blocked >&2; exit 2; fi\nexit 0\n"
	scripts := map[string]string{
		"codex-hook.sh":       "#!/usr/bin/env bash\nFAIL_MODE=\"${DEFENSECLAW_FAIL_MODE:-open}\"\n" + outage,
		"claude-code-hook.sh": "#!/usr/bin/env bash\nif [ \"open\" = \"closed\" ] || [ \"${DEFENSECLAW_STRICT_AVAILABILITY:-}\" = \"1\" ]; then exit 2; fi\nFAIL_MODE=\"open\"\n" + outage,
		"cursor-hook.sh":      "#!/usr/bin/env bash\n_DC_HOME_FAIL_MODE=\"open\"\nFAIL_MODE=\"${DEFENSECLAW_FAIL_MODE:-closed}\"\n" + outage,
		"copilot-hook.sh":     "#!/usr/bin/env bash\nFAIL_MODE=\"open\"\n" + outage,
	}
	for name, body := range scripts {
		write(name, body, 0o700)
	}
	run := func(name string) int {
		t.Helper()
		cmd := exec.Command("bash", filepath.Join(hookDir, name))
		cmd.Env = append(os.Environ(), "DEFENSECLAW_FAIL_MODE=open")
		if err := cmd.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				return exit.ExitCode()
			}
			t.Fatal(err)
		}
		return 0
	}
	canRun := runtime.GOOS != "windows"
	if canRun {
		if _, err := exec.LookPath("bash"); err != nil {
			canRun = false
		}
	}
	if canRun {
		for _, name := range []string{"codex-hook.sh", "claude-code-hook.sh", "copilot-hook.sh"} {
			if got := run(name); got != 0 {
				t.Fatalf("%s before the refresh exits %d, want 0 (fail open)", name, got)
			}
		}
	}

	modes := map[string]string{"": "closed", "codex": "closed", "claudecode": "closed", "cursor": "closed", "kiro": "closed", "copilot": "open"}
	refreshed, err := RefreshHookFailModes(hookDir, func(name string) string { return modes[name] })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(refreshed.Sidecar, []string{"kiro", "legacy"}) ||
		!reflect.DeepEqual(refreshed.Scripts, []string{"claude-code-hook.sh", "codex-hook.sh", "cursor-hook.sh"}) {
		t.Fatalf("refreshed %+v", refreshed)
	}
	state := readHookConfigSidecarForTest(t, hookDir)
	if state.Version != 2 || state.GatewayAddr != "127.0.0.1:18970" || state.LegacyMode != "closed" ||
		state.LegacySource != HookFailModeSourceConfig || state.FailModes["kiro"] != "closed" {
		t.Fatalf("sidecar after refresh: %+v", state)
	}
	if got := readFlatHookRecordForTest(t, hookDir, "kiro"); legacyHookConfigValue([]byte(got), "DEFENSECLAW_FAIL_MODE") != "closed" {
		t.Fatalf("kiro flat record %q", got)
	}
	if got := readFlatHookRecordForTest(t, hookDir, "legacy"); legacyHookConfigValue([]byte(got), "DEFENSECLAW_FAIL_MODE") != "closed" {
		t.Fatalf("legacy flat record %q", got)
	}
	for _, name := range []string{"codex-hook.sh", "claude-code-hook.sh", "cursor-hook.sh"} {
		body, err := os.ReadFile(filepath.Join(hookDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), `"open"`) || strings.Contains(string(body), "DEFENSECLAW_FAIL_MODE:-") {
			t.Fatalf("%s still opens:\n%s", name, body)
		}
		if info, err := os.Stat(filepath.Join(hookDir, name)); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o700) {
			t.Fatalf("%s mode %v (%v)", name, info.Mode(), err)
		}
	}
	if body, _ := os.ReadFile(filepath.Join(hookDir, "copilot-hook.sh")); string(body) != scripts["copilot-hook.sh"] {
		t.Fatalf("the operator's open copilot hook was changed:\n%s", body)
	}
	if canRun {
		for _, name := range []string{"codex-hook.sh", "claude-code-hook.sh", "cursor-hook.sh"} {
			if got := run(name); got != 2 {
				t.Fatalf("%s after the refresh exits %d, want 2 (fail closed)", name, got)
			}
		}
		if got := run("copilot-hook.sh"); got != 0 {
			t.Fatalf("the operator's open copilot hook exits %d, want 0", got)
		}
	}
	// A second pass (after the gateway stopped) changes no script again.
	again, err := RefreshHookFailModes(hookDir, func(name string) string { return modes[name] })
	if err != nil || again.Scripts != nil {
		t.Fatalf("second refresh %+v %v", again, err)
	}
}

// The shared inspect scripts of this release follow an open from the hook
// runtime records only when its config source is recorded: an earlier
// release's record (or a peer entry it left) and an open CapableHookFailMode
// lowered fail closed while the gateway is down.
func TestSharedShellReaderFollowsOnlyAnOpenTheConfigChose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, jq := exec.LookPath("jq")
	_, python := exec.LookPath("python3")
	jsonReadable := jq == nil || python == nil
	for _, test := range []struct {
		name, flat, sidecar, want string
		needsJSON                 bool
	}{
		{name: "earlier release's flat open", flat: "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=open\n", want: "closed"},
		{name: "flat open from the config", flat: "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=open\nFAIL_MODE_SOURCE=config\n", want: "open"},
		{name: "flat closed", flat: "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=closed\nFAIL_MODE_SOURCE=config\n", want: "closed"},
		{name: "earlier release's JSON open", sidecar: `{"version":2,"fail_modes":{"codex":"open"}}`, want: "closed"},
		{name: "JSON open from the config", sidecar: `{"version":2,"fail_modes":{"codex":"open"},"fail_mode_sources":{"codex":"config"}}`, want: "open", needsJSON: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.needsJSON && !jsonReadable {
				t.Skip("neither jq nor python3 is installed")
			}
			hookDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(hookDir, "_hardening.sh"), helper, 0o600); err != nil {
				t.Fatal(err)
			}
			if test.flat != "" {
				if err := os.WriteFile(filepath.Join(hookDir, hookConfigSidecarName+".codex"), []byte(test.flat), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if test.sidecar != "" {
				if err := os.WriteFile(filepath.Join(hookDir, hookConfigSidecarName), []byte(test.sidecar), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "-c", `. "$1/_hardening.sh"; defenseclaw_shared_runtime_fail_mode "$1" codex`, "test", hookDir)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("reader: %v", err)
			}
			if got := string(out); got != test.want {
				t.Fatalf("fail mode %q, want %q", got, test.want)
			}
		})
	}
}
