// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// until 1.1: guard the removal while older configs may still carry these IDs.
func TestRemovedConnectorsUnavailable(t *testing.T) {
	registry := NewDefaultRegistry()
	for _, name := range []string{"openhands", "omnigent"} {
		if IsKnownBuiltinConnector(name) {
			t.Errorf("%s is still a built-in connector", name)
		}
		if _, found := registry.Get(name); found {
			t.Errorf("%s is still in the default registry", name)
		}
	}
}

// The removed IDs resolve only to a teardown-only connector that never sets
// up, authenticates or routes anything.
func TestRemovedConnectorsAreTeardownOnly(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"openhands", "openhands"}, {"Open-Hands", "openhands"}, {"OMNIGENT", "omnigent"},
	} {
		conn, ok := RetiredConnector(tc.name)
		if !ok || conn.Name() != tc.want {
			t.Fatalf("RetiredConnector(%q) = %v, %v; want %s", tc.name, conn, ok, tc.want)
		}
		if err := conn.Setup(context.Background(), SetupOpts{DataDir: t.TempDir()}); err == nil ||
			!strings.Contains(err.Error(), "removed in DefenseClaw 1.0.4") {
			t.Fatalf("%s Setup = %v, want the removal refusal", tc.want, err)
		}
		if conn.Authenticate(nil) {
			t.Fatalf("%s authenticated hook traffic", tc.want)
		}
		if _, err := conn.Route(nil, nil); err == nil {
			t.Fatalf("%s routed hook traffic", tc.want)
		}
	}
}

// What older releases wrote into OmniGent's config.yaml.
const (
	removedOmnigentHandler   = removedOmnigentModuleName + ".defenseclaw_policy"
	removedOmnigentPolicyKey = "defenseclaw_guardrail"
	// removedOmnigentRendered stands for a policy module an older release
	// rendered: it starts with the template's marker line.
	removedOmnigentRendered = removedOmnigentPolicyMarker + "\n\"\"\"OmniGent custom policy bridge installed by DefenseClaw.\"\"\"\n\ndef defenseclaw_policy(event):\n    pass\n"
)

func writeRemovedFixture(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// removedOpenHandsHooksDoc renders the hooks.json an older release wrote:
// the operator's own hook next to DefenseClaw's matcher group per event.
func removedOpenHandsHooksDoc(t *testing.T, script string) string {
	t.Helper()
	operator := map[string]interface{}{"matcher": "*", "hooks": []interface{}{
		map[string]interface{}{"type": "command", "command": "/usr/local/bin/audit-hook"},
	}}
	doc := map[string]interface{}{}
	for _, event := range []string{"pre_tool_use", "post_tool_use", "user_prompt_submit", "stop"} {
		groups := []interface{}{map[string]interface{}{"matcher": "*", "hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": shellWord(script), "timeout": 60},
		}}}
		if event == "pre_tool_use" {
			groups = append([]interface{}{operator}, groups...)
		}
		doc[event] = groups
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// An older release's OpenHands registration is removed on upgrade and
// uninstall: an unchanged file goes back to what the operator had, an
// edited one (or one without a backup, GAP-1926) loses only DefenseClaw's
// hooks, and the hook script turns into the disabled tombstone.
func TestRemovedOpenHandsTeardownRemovesOwnHooks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenHands was never set up on Windows")
	}
	operatorDoc := `{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/audit-hook"}]}]}`
	for _, tc := range []string{"unchanged", "edited", "no backup", "config home"} {
		t.Run(tc, func(t *testing.T) {
			home := t.TempDir()
			restoreHome, err := BindUserHomeDir(home)
			if err != nil {
				t.Fatal(err)
			}
			defer restoreHome()
			dataDir := filepath.Join(home, ".defenseclaw")
			hooksPath := filepath.Join(home, ".openhands", "hooks.json")
			opts := SetupOpts{DataDir: dataDir}
			if tc == "config home" {
				configHome := filepath.Join(t.TempDir(), "openhands-home")
				hooksPath = filepath.Join(configHome, "hooks.json")
				opts.ConfigHome = configHome
			}
			script := filepath.Join(dataDir, "hooks", removedOpenHandsHookScript)
			writeRemovedFixture(t, script, "#!/bin/sh\n# defenseclaw-managed-hook v1\n", 0o700)
			writeRemovedFixture(t, filepath.Join(dataDir, "hooks", ".hookcfg.openhands"), "DEFENSECLAW_CONNECTOR=openhands\n", 0o600)
			writeRemovedFixture(t, filepath.Join(dataDir, "hooks", ".otlp-openhands.token"), strings.Repeat("a", 64)+"\n", 0o600)
			writeRemovedFixture(t, hooksPath, operatorDoc, 0o600)
			if tc != "no backup" {
				if err := captureManagedFileBackup(dataDir, "openhands", "config", hooksPath); err != nil {
					t.Fatal(err)
				}
			}
			writeRemovedFixture(t, hooksPath, removedOpenHandsHooksDoc(t, script), 0o600)
			if tc != "no backup" {
				if err := updateManagedFileBackupPostHash(dataDir, "openhands", "config", hooksPath); err != nil {
					t.Fatal(err)
				}
			}
			if tc == "edited" {
				var doc map[string]interface{}
				data, _ := os.ReadFile(hooksPath)
				if err := json.Unmarshal(data, &doc); err != nil {
					t.Fatal(err)
				}
				doc["session_start"] = []interface{}{map[string]interface{}{"matcher": "*", "hooks": []interface{}{
					map[string]interface{}{"type": "command", "command": "/usr/local/bin/notify"},
				}}}
				data, _ = json.Marshal(doc)
				writeRemovedFixture(t, hooksPath, string(data), 0o600)
			}

			conn, _ := RetiredConnector("openhands")
			if err := conn.VerifyClean(opts); err == nil {
				t.Fatal("VerifyClean passed while hooks.json still runs DefenseClaw's hook")
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean after teardown: %v", err)
			}
			data, err := os.ReadFile(hooksPath)
			if err != nil {
				t.Fatal(err)
			}
			got := string(data)
			if strings.Contains(got, script) || !strings.Contains(got, "/usr/local/bin/audit-hook") {
				t.Fatalf("hooks.json after teardown = %s", got)
			}
			if tc == "unchanged" && strings.TrimSpace(got) != operatorDoc {
				t.Fatalf("unchanged hooks.json was not restored: %s", got)
			}
			if tc == "edited" && !strings.Contains(got, "/usr/local/bin/notify") {
				t.Fatalf("the operator's later edit was lost: %s", got)
			}
			for _, event := range []string{"post_tool_use", "user_prompt_submit", "stop"} {
				if strings.Contains(got, `"`+event+`"`) {
					t.Fatalf("DefenseClaw's emptied %s group stayed: %s", event, got)
				}
			}
			body, err := os.ReadFile(script)
			if err != nil || !strings.Contains(string(body), "disabled tombstone") {
				t.Fatalf("hook script is not the disabled tombstone: %q, %v", body, err)
			}
			for _, gone := range []string{
				filepath.Join(dataDir, "hooks", ".hookcfg.openhands"),
				filepath.Join(dataDir, "hooks", ".otlp-openhands.token"),
				managedFileBackupPath(dataDir, "openhands", "config"),
			} {
				if _, err := os.Lstat(gone); !os.IsNotExist(err) {
					t.Fatalf("%s survived teardown: %v", gone, err)
				}
			}
			// A second run (the next boot, then uninstall) has nothing to do.
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("second Teardown: %v", err)
			}
		})
	}
}

// A host that never ran OpenHands is left alone: no hooks file, no
// tombstone.
func TestRemovedOpenHandsTeardownCreatesNothing(t *testing.T) {
	home := t.TempDir()
	restoreHome, err := BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	defer restoreHome()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	conn, _ := RetiredConnector("openhands")
	if err := conn.Teardown(context.Background(), SetupOpts{DataDir: dataDir}); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	for _, path := range []string{
		filepath.Join(home, ".openhands"),
		filepath.Join(dataDir, "hooks", removedOpenHandsHookScript),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("teardown created %s: %v", path, err)
		}
	}
}

// An older release's OmniGent policy (config.yaml entries, the policy module
// in the data directory and the .pth file that put it on OmniGent's import
// path) is removed; the operator's own policies stay.
func TestRemovedOmnigentTeardownRemovesPolicy(t *testing.T) {
	operatorConfig := "server: http://127.0.0.1:7000\npolicy_modules:\n  - corp_policy\npolicies:\n  corp:\n    handler: corp_policy.check\n"
	patchedConfig := "server: http://127.0.0.1:7000\npolicy_modules:\n  - corp_policy\n  - " + removedOmnigentModuleName +
		"\npolicies:\n  corp:\n    handler: corp_policy.check\n  " + removedOmnigentPolicyKey + ":\n    handler: " + removedOmnigentHandler + "\n"
	for _, tc := range []string{"unchanged", "edited", "no backup", "config home"} {
		t.Run(tc, func(t *testing.T) {
			home := t.TempDir()
			restoreHome, err := BindUserHomeDir(home)
			if err != nil {
				t.Fatal(err)
			}
			defer restoreHome()
			t.Setenv("OMNIGENT_CONFIG_HOME", "")
			dataDir := filepath.Join(home, ".defenseclaw")
			opts := SetupOpts{DataDir: dataDir}
			configPath := filepath.Join(home, ".omnigent", "config.yaml")
			if tc == "config home" {
				opts.ConfigHome = filepath.Join(t.TempDir(), "omnigent-home")
				configPath = filepath.Join(opts.ConfigHome, "config.yaml")
			}
			modulePath := filepath.Join(dataDir, "hooks", removedOmnigentModuleName+".py")
			pthPath := filepath.Join(t.TempDir(), "site-packages", "defenseclaw_omnigent.pth")
			writeRemovedFixture(t, configPath, operatorConfig, 0o600)
			backup := tc != "no backup"
			if backup {
				for logical, path := range map[string]string{"config": configPath, "module": modulePath, "pth": pthPath} {
					if err := captureManagedFileBackup(dataDir, "omnigent", logical, path); err != nil {
						t.Fatal(err)
					}
				}
			}
			writeRemovedFixture(t, configPath, patchedConfig, 0o600)
			writeRemovedFixture(t, modulePath, removedOmnigentRendered, 0o600)
			writeRemovedFixture(t, pthPath, filepath.Dir(modulePath)+"\n", 0o600)
			if backup {
				for logical, path := range map[string]string{"config": configPath, "module": modulePath, "pth": pthPath} {
					if err := updateManagedFileBackupPostHash(dataDir, "omnigent", logical, path); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc == "edited" {
				writeRemovedFixture(t, configPath, patchedConfig+"model: local\n", 0o600)
			}

			conn, _ := RetiredConnector("omnigent")
			if err := conn.VerifyClean(opts); err == nil {
				t.Fatal("VerifyClean passed while config.yaml still loads DefenseClaw's policy")
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean after teardown: %v", err)
			}
			data, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			got := string(data)
			if strings.Contains(got, removedOmnigentModuleName) || strings.Contains(got, removedOmnigentPolicyKey) ||
				!strings.Contains(got, "corp_policy") || !strings.Contains(got, "corp_policy.check") {
				t.Fatalf("config.yaml after teardown = %s", got)
			}
			if tc == "unchanged" && got != operatorConfig {
				t.Fatalf("unchanged config.yaml was not restored: %s", got)
			}
			if tc == "edited" && !strings.Contains(got, "model: local") {
				t.Fatalf("the operator's later edit was lost: %s", got)
			}
			if _, err := os.Lstat(modulePath); !os.IsNotExist(err) {
				t.Fatalf("policy module survived teardown: %v", err)
			}
			if _, err := os.Lstat(pthPath); backup && !os.IsNotExist(err) {
				t.Fatalf("import-path file survived teardown: %v", err)
			}
			for _, logical := range []string{"config", "module", "pth"} {
				if _, err := os.Lstat(managedFileBackupPath(dataDir, "omnigent", logical)); !os.IsNotExist(err) {
					t.Fatalf("%s backup survived teardown: %v", logical, err)
				}
			}
		})
	}
}

// Only DefenseClaw's own policy entry goes: one named like it whose handler
// is the operator's stays.
func TestRemovedOmnigentConfigCleanupKeepsForeignEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "policy_modules: " + removedOmnigentModuleName + "\npolicies:\n  " + removedOmnigentPolicyKey + ":\n    handler: corp.check\n"
	writeRemovedFixture(t, path, body, 0o600)
	if err := removeRemovedOmnigentConfigEntries(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	got := string(data)
	if strings.Contains(got, "policy_modules") || !strings.Contains(got, "corp.check") {
		t.Fatalf("config.yaml after cleanup = %s", got)
	}
	if err := removeRemovedOmnigentConfigEntries(filepath.Join(t.TempDir(), "missing.yaml")); err != nil {
		t.Fatalf("missing config: %v", err)
	}
}
