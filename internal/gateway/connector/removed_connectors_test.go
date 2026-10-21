// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: the teardown-only OpenHands and OmniGent connectors (removed.go).
// Delete with that file.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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

// --- shared fixture ---

const removedMissing = "<missing>"

func writeRemovedFixture(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// removedSnapshot reads each path ("<missing>" when absent).
func removedSnapshot(t *testing.T, paths ...string) map[string]string {
	t.Helper()
	out := make(map[string]string, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		switch {
		case os.IsNotExist(err):
			out[path] = removedMissing
		case err != nil:
			t.Fatal(err)
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				t.Fatal(err)
			}
			out[path] = "symlink:" + target
		default:
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			out[path] = string(data)
		}
	}
	return out
}

func removedTokenFile(t *testing.T, dataDir, connectorName string) string {
	t.Helper()
	path, err := HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func requireRemovedSnapshot(t *testing.T, what string, want map[string]string) {
	t.Helper()
	paths := make([]string, 0, len(want))
	for path := range want {
		paths = append(paths, path)
	}
	got := removedSnapshot(t, paths...)
	for path, body := range want {
		if got[path] != body {
			t.Fatalf("%s changed %s:\n got %q\nwant %q", what, path, got[path], body)
		}
	}
}

// removedHarness is a home and data directory where an older release set up
// a removed connector next to a surviving one (Codex).
type removedHarness struct {
	home, dataDir string
	opts          SetupOpts
	notices       *bytes.Buffer
	peer          map[string]string
}

func newRemovedHarness(t *testing.T) *removedHarness {
	t.Helper()
	home := t.TempDir()
	restoreHome, err := BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	t.Setenv("OMNIGENT_CONFIG_HOME", "")
	notices := &bytes.Buffer{}
	previous := removedConnectorNotices
	removedConnectorNotices = notices
	t.Cleanup(func() { removedConnectorNotices = previous })
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureHookAPIToken(dataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	codexScript := filepath.Join(dataDir, "hooks", "codex-hook.sh")
	writeRemovedFixture(t, codexConfig, "[hooks]\ncommand = \""+codexScript+"\"\n", 0o600)
	writeRemovedFixture(t, codexScript, "#!/bin/sh\n# defenseclaw-managed-hook v1\n", 0o700)
	writeRemovedFixture(t, filepath.Join(dataDir, "hooks", ".hookcfg.codex"), "DEFENSECLAW_CONNECTOR=codex\n", 0o600)
	h := &removedHarness{home: home, dataDir: dataDir, opts: SetupOpts{DataDir: dataDir}, notices: notices}
	h.peer = removedSnapshot(t, codexConfig, codexScript,
		filepath.Join(dataDir, "hooks", ".hookcfg.codex"),
		removedTokenFile(t, dataDir, "codex"))
	if token, err := LoadHookAPIToken(dataDir, "codex"); err != nil || token == "" {
		t.Fatalf("codex token = %q, %v", token, err)
	}
	return h
}

// requirePeerUnchanged checks the surviving connector's files and token.
func (h *removedHarness) requirePeerUnchanged(t *testing.T) {
	t.Helper()
	requireRemovedSnapshot(t, "a removed connector's teardown", h.peer)
	if token, err := LoadHookAPIToken(h.dataDir, "codex"); err != nil || token == "" {
		t.Fatalf("the surviving connector's token = %q, %v", token, err)
	}
}

// recordSetup does what an older setup did for one file: record the file it
// found, then write body ("" with created=false leaves no file).
func (h *removedHarness) recordSetup(t *testing.T, connectorName, logical, path, before string, existed bool, body string) {
	t.Helper()
	if existed {
		writeRemovedFixture(t, path, before, 0o600)
	} else if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := captureManagedFileBackup(h.dataDir, connectorName, logical, path); err != nil {
		t.Fatal(err)
	}
	writeRemovedFixture(t, path, body, 0o600)
	if err := updateManagedFileBackupPostHash(h.dataDir, connectorName, logical, path); err != nil {
		t.Fatal(err)
	}
}

func (h *removedHarness) manualRecord(t *testing.T, connectorName string) (removedCleanupRecord, bool) {
	t.Helper()
	data, err := os.ReadFile(removedCleanupRecordPath(h.dataDir, connectorName))
	if os.IsNotExist(err) {
		return removedCleanupRecord{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	var record removedCleanupRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("manual cleanup record: %v", err)
	}
	return record, true
}

func skipWhereModesDoNotBind(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("directory modes do not stop writes on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
}

// --- OmniGent ---

const (
	omnigentOperatorConfig = "server: http://127.0.0.1:7000\npolicy_modules:\n  - corp_policy\npolicies:\n  corp:\n    handler: corp_policy.check\n"
	omnigentPatchedConfig  = "server: http://127.0.0.1:7000\npolicy_modules:\n  - corp_policy\n  - " + removedOmnigentModuleName +
		"\npolicies:\n  corp:\n    handler: corp_policy.check\n  defenseclaw_guardrail:\n    handler: " + removedOmnigentModuleName + ".defenseclaw_policy\n"
	// omnigentCleanedConfig is what a user leaves after removing
	// DefenseClaw's entries by hand.
	omnigentCleanedConfig = omnigentOperatorConfig + "model: local\n"
	omnigentModule        = "# defenseclaw-managed-policy v1\n\"\"\"OmniGent custom policy bridge installed by DefenseClaw.\"\"\"\n\ndef defenseclaw_policy(event):\n    pass\n"
)

type omnigentSetup struct {
	// config is what config.yaml held before setup; configCreated: there
	// was none.
	config        string
	configCreated bool
	// pth is what the .pth file held before setup ("" = none).
	pth string
	// module is an older module setup replaced ("" = none).
	module string
}

type omnigentHarness struct {
	*removedHarness
	configPath, modulePath, pthPath, hookDir string
	// keptModule is the module a finished cleanup leaves ("" = none).
	keptModule string
}

func newOmnigentHarness(t *testing.T, configHome bool) *omnigentHarness {
	t.Helper()
	h := &omnigentHarness{removedHarness: newRemovedHarness(t)}
	h.configPath = filepath.Join(h.home, ".omnigent", "config.yaml")
	if configHome {
		h.opts.ConfigHome = filepath.Join(t.TempDir(), "omnigent-home")
		h.configPath = filepath.Join(h.opts.ConfigHome, "config.yaml")
	}
	h.modulePath = filepath.Join(h.dataDir, "hooks", removedOmnigentModuleName+".py")
	h.hookDir = filepath.Dir(h.modulePath)
	h.pthPath = filepath.Join(t.TempDir(), "site-packages", "defenseclaw_omnigent.pth")
	if _, err := EnsureHookAPIToken(h.dataDir, removedOmnigentID); err != nil {
		t.Fatal(err)
	}
	return h
}

// setUp writes what an older release's OmniGent setup wrote, with its
// backup records.
func (h *omnigentHarness) setUp(t *testing.T, s omnigentSetup) {
	t.Helper()
	h.recordSetup(t, removedOmnigentID, "config", h.configPath, s.config, !s.configCreated, omnigentPatchedConfig)
	// Setup wrote the .pth with DefenseClaw's line alone.
	h.recordSetup(t, removedOmnigentID, "pth", h.pthPath, s.pth, s.pth != "", h.hookDir+"\n")
	h.recordSetup(t, removedOmnigentID, "module", h.modulePath, s.module, s.module != "", omnigentModule)
}

func (h *omnigentHarness) records() []string {
	var out []string
	for _, logical := range []string{"config", "pth", "module"} {
		out = append(out, managedFileBackupPath(h.dataDir, removedOmnigentID, logical))
	}
	return out
}

// state is every file the OmniGent teardown could touch.
func (h *omnigentHarness) state(t *testing.T, extra ...string) map[string]string {
	t.Helper()
	paths := append([]string{h.configPath, h.pthPath, h.modulePath, removedTokenFile(t, h.dataDir, removedOmnigentID)}, h.records()...)
	return removedSnapshot(t, append(paths, extra...)...)
}

func (h *omnigentHarness) teardown(t *testing.T) error {
	t.Helper()
	conn, _ := RetiredConnector(removedOmnigentID)
	return conn.Teardown(context.Background(), h.opts)
}

func (h *omnigentHarness) verify() error {
	conn, _ := RetiredConnector(removedOmnigentID)
	return conn.VerifyClean(h.opts)
}

// requireDone checks a finished cleanup: nothing of DefenseClaw's is left,
// the token is revoked, the records are gone and the peer is untouched.
func (h *omnigentHarness) requireDone(t *testing.T) {
	t.Helper()
	if err := h.verify(); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
	if data, err := os.ReadFile(h.configPath); err == nil {
		if names, err := removedOmnigentConfigNames(data); names || err != nil {
			t.Fatalf("config.yaml still names the module (%v): %s", err, data)
		}
	}
	if data, err := os.ReadFile(h.pthPath); err == nil && strings.Contains(string(data), h.hookDir) {
		t.Fatalf(".pth still names the hook directory: %q", data)
	}
	if h.keptModule != "" {
		requireRemovedSnapshot(t, "teardown", map[string]string{h.modulePath: h.keptModule})
	} else if _, err := os.Lstat(h.modulePath); !os.IsNotExist(err) {
		t.Fatalf("policy module survived: %v", err)
	}
	for _, record := range h.records() {
		if _, err := os.Lstat(record); !os.IsNotExist(err) {
			t.Fatalf("%s survived: %v", record, err)
		}
	}
	if token, err := LoadHookAPIToken(h.dataDir, removedOmnigentID); err != nil || token != "" {
		t.Fatalf("omnigent token = %q, %v; want revoked", token, err)
	}
	if _, ok := h.manualRecord(t, removedOmnigentID); ok {
		t.Fatal("the manual cleanup record survived a finished cleanup")
	}
	h.requirePeerUnchanged(t)
}

// Files exactly as an older setup wrote them are put back the way setup found
// them (or removed when setup created them), all three together; the token is
// revoked, the surviving connector is untouched, and a second run is a no-op.
func TestRemovedOmnigentTeardownUndoesByteIdenticalSetup(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configHome bool
		setup      omnigentSetup
		// edit runs after setup: a change that leaves nothing of
		// DefenseClaw's in the file, so teardown may go on.
		edit       func(h *omnigentHarness)
		wantConfig string
		wantPth    string
	}{
		{name: "config existed", setup: omnigentSetup{config: omnigentOperatorConfig}, wantConfig: omnigentOperatorConfig, wantPth: removedMissing},
		{name: "config created by setup", setup: omnigentSetup{configCreated: true}, wantConfig: removedMissing, wantPth: removedMissing},
		{name: "config home", configHome: true, setup: omnigentSetup{config: omnigentOperatorConfig}, wantConfig: omnigentOperatorConfig, wantPth: removedMissing},
		{name: "pth had a user line", setup: omnigentSetup{config: omnigentOperatorConfig, pth: "/opt/user-site\n"}, wantConfig: omnigentOperatorConfig, wantPth: "/opt/user-site\n"},
		{name: "older module replaced", setup: omnigentSetup{config: omnigentOperatorConfig, module: "# defenseclaw-managed-policy v1\n# older\n"}, wantConfig: omnigentOperatorConfig, wantPth: removedMissing},
		{
			name:  "user already removed DefenseClaw from config",
			setup: omnigentSetup{config: omnigentOperatorConfig},
			edit: func(h *omnigentHarness) {
				_ = os.WriteFile(h.configPath, []byte(omnigentCleanedConfig+"# was "+removedOmnigentModuleName+"\n"), 0o600)
			},
			wantConfig: omnigentCleanedConfig + "# was " + removedOmnigentModuleName + "\n",
			wantPth:    removedMissing,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOmnigentHarness(t, tc.configHome)
			h.setUp(t, tc.setup)
			if tc.edit != nil {
				tc.edit(h)
			}
			if err := h.verify(); err == nil || !strings.Contains(err.Error(), "as DefenseClaw wrote it") {
				t.Fatalf("VerifyClean before teardown = %v, want the remaining state named", err)
			}
			for run := 1; run <= 2; run++ {
				if err := h.teardown(t); err != nil {
					t.Fatalf("Teardown run %d: %v", run, err)
				}
				h.requireDone(t)
			}
			requireRemovedSnapshot(t, "teardown", map[string]string{h.configPath: tc.wantConfig, h.pthPath: tc.wantPth})
			if h.notices.Len() != 0 {
				t.Fatalf("a clean teardown printed: %s", h.notices)
			}
		})
	}
}

// A file that is not exactly as DefenseClaw wrote it and still names
// DefenseClaw (or cannot be read) stops the whole cleanup: every file, record
// and the token stay byte for byte, one warning names the file and its step,
// the steps are recorded, and VerifyClean accepts the recorded state so the
// surviving connectors come up. Once the user does the step, the next
// teardown removes the rest.
func TestRemovedOmnigentTeardownLeavesUnprovableStateUntouched(t *testing.T) {
	escaped := "policy_modules:\n  - corp_policy\n  - \"defenseclaw_omnigent_\\x70olicy\"\npolicies:\n  g:\n    handler: \"defenseclaw_omnigent_\\u0070olicy.defenseclaw_policy\"\n"
	for _, tc := range []struct {
		name  string
		setup omnigentSetup
		// drift makes the unprovable state and returns the file the
		// warning must name; fix does the recorded step.
		drift func(t *testing.T, h *omnigentHarness) string
		fix   func(t *testing.T, h *omnigentHarness)
	}{
		{
			name: "config edited", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				writeRemovedFixture(t, h.configPath, omnigentPatchedConfig+"model: local\n", 0o600)
				return h.configPath
			},
		},
		{
			name: "config names the module through YAML escapes", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				writeRemovedFixture(t, h.configPath, escaped, 0o600)
				return h.configPath
			},
		},
		{
			name: "config names the module in a !!binary value", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				writeRemovedFixture(t, h.configPath, "policy_modules: [corp_policy, !!binary ZGVmZW5zZWNsYXdfb21uaWdlbnRfcG9saWN5]\n", 0o600)
				return h.configPath
			},
		},
		{
			name: "config names the module through a merge key", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				writeRemovedFixture(t, h.configPath, "x-base: &base\n  policy_modules: ["+removedOmnigentModuleName+"]\n<<: *base\nmodel: local\n", 0o600)
				return h.configPath
			},
		},
		{
			name: "config sets a key twice", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				writeRemovedFixture(t, h.configPath, "policies:\n  g:\n    handler: "+removedOmnigentModuleName+".defenseclaw_policy\n    handler: corp_policy.check\n", 0o600)
				return h.configPath
			},
		},
		{
			name: "config names the module in a second document", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				writeRemovedFixture(t, h.configPath, "model: local\n---\npolicy_modules: ["+removedOmnigentModuleName+"]\n", 0o600)
				return h.configPath
			},
		},
		{
			name: "config is not valid YAML", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				writeRemovedFixture(t, h.configPath, "policy_modules: [corp\n", 0o600)
				return h.configPath
			},
		},
		{
			name: "config is a symlink", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				if runtime.GOOS == "windows" {
					t.Skip("symlinks need privileges on Windows")
				}
				target := filepath.Join(t.TempDir(), "shared.yaml")
				writeRemovedFixture(t, target, omnigentPatchedConfig, 0o600)
				if err := os.Remove(h.configPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, h.configPath); err != nil {
					t.Fatal(err)
				}
				return h.configPath
			},
			fix: func(t *testing.T, h *omnigentHarness) {
				if err := os.Remove(h.configPath); err != nil {
					t.Fatal(err)
				}
				writeRemovedFixture(t, h.configPath, omnigentCleanedConfig, 0o600)
			},
		},
		{
			name: "config without a record", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				discardManagedFileBackup(h.dataDir, removedOmnigentID, "config")
				return h.configPath
			},
		},
		{
			name: "saved copy of config names the module (GAP-1926)", setup: omnigentSetup{config: omnigentPatchedConfig},
			drift: func(t *testing.T, h *omnigentHarness) string { return h.configPath },
		},
		{
			name: "another OmniGent config home names the module", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				other := filepath.Join(h.home, "omnigent-env")
				t.Setenv("OMNIGENT_CONFIG_HOME", other)
				path := filepath.Join(other, "config.yaml")
				writeRemovedFixture(t, path, omnigentPatchedConfig, 0o600)
				return path
			},
			fix: func(t *testing.T, h *omnigentHarness) {
				writeRemovedFixture(t, filepath.Join(h.home, "omnigent-env", "config.yaml"), omnigentCleanedConfig, 0o600)
			},
		},
		{
			name: "pth edited", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				writeRemovedFixture(t, h.pthPath, h.hookDir+"\r\n/opt/user-site\n", 0o600)
				return h.pthPath
			},
			fix: func(t *testing.T, h *omnigentHarness) { writeRemovedFixture(t, h.pthPath, "/opt/user-site\n", 0o600) },
		},
		{
			name: "module edited", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				writeRemovedFixture(t, h.modulePath, omnigentModule+"# my tweak\n", 0o600)
				return h.modulePath
			},
			fix: func(t *testing.T, h *omnigentHarness) { _ = os.Remove(h.modulePath) },
		},
		{
			name: "module without a record", setup: omnigentSetup{config: omnigentOperatorConfig},
			drift: func(t *testing.T, h *omnigentHarness) string {
				discardManagedFileBackup(h.dataDir, removedOmnigentID, "module")
				return h.modulePath
			},
			fix: func(t *testing.T, h *omnigentHarness) { _ = os.Remove(h.modulePath) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOmnigentHarness(t, false)
			h.setUp(t, tc.setup)
			left := tc.drift(t, h)
			other := filepath.Join(h.home, "omnigent-env", "config.yaml")
			before := h.state(t, other)
			for run := 1; run <= 2; run++ {
				h.notices.Reset()
				if err := h.teardown(t); err != nil {
					t.Fatalf("Teardown run %d = %v, want the state left for manual cleanup", run, err)
				}
				requireRemovedSnapshot(t, "a teardown that cannot prove ownership", before)
				h.requirePeerUnchanged(t)
				if got := strings.Count(h.notices.String(), "WARNING"); got != 1 || !strings.Contains(h.notices.String(), left) ||
					!strings.Contains(h.notices.String(), "defenseclaw-gateway connector teardown --connector omnigent") {
					t.Fatalf("run %d printed %d warnings, want one naming %s and the finish command:\n%s", run, got, left, h.notices)
				}
				record, ok := h.manualRecord(t, removedOmnigentID)
				if !ok || !record.lists(left) || record.Label != "OmniGent" || record.Finish == "" {
					t.Fatalf("manual cleanup record = %+v, %v; want it to list %s", record, ok, left)
				}
				for _, item := range record.Items {
					if item.Reason == "" || item.Step == "" {
						t.Fatalf("manual cleanup item without a reason or step: %+v", item)
					}
				}
				if err := h.verify(); err != nil {
					t.Fatalf("VerifyClean with the steps recorded: %v", err)
				}
			}
			// Without the record the same state is not clean.
			if err := os.Remove(removedCleanupRecordPath(h.dataDir, removedOmnigentID)); err != nil {
				t.Fatal(err)
			}
			if err := h.verify(); err == nil || !strings.Contains(err.Error(), left) {
				t.Fatalf("VerifyClean without the record = %v, want %s named", err, left)
			}

			if tc.fix != nil {
				tc.fix(t, h)
			} else {
				writeRemovedFixture(t, h.configPath, omnigentCleanedConfig, 0o600)
			}
			h.notices.Reset()
			if err := h.teardown(t); err != nil {
				t.Fatalf("Teardown after the manual step: %v", err)
			}
			if h.notices.Len() != 0 {
				t.Fatalf("finished teardown printed: %s", h.notices)
			}
			h.requireDone(t)
		})
	}
}

// A change that fails rolls back every change made before it: no file is left
// half cleaned, the records and the token stay, VerifyClean fails (so the
// gateway retries), and the retry finishes once the cause is gone.
func TestRemovedOmnigentFailedCleanupLeavesNoPartialState(t *testing.T) {
	skipWhereModesDoNotBind(t)
	for _, tc := range []struct {
		name string
		dir  func(h *omnigentHarness) string
	}{
		{"config cannot be restored", func(h *omnigentHarness) string { return filepath.Dir(h.configPath) }},
		{".pth cannot be removed", func(h *omnigentHarness) string { return filepath.Dir(h.pthPath) }},
		{"module cannot be removed", func(h *omnigentHarness) string { return h.hookDir }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOmnigentHarness(t, false)
			h.setUp(t, omnigentSetup{config: omnigentOperatorConfig})
			before := h.state(t)
			dir := tc.dir(h)
			if err := os.Chmod(dir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			for run := 1; run <= 2; run++ {
				if err := h.teardown(t); err == nil {
					t.Fatalf("Teardown run %d succeeded with %s read-only", run, dir)
				}
				requireRemovedSnapshot(t, "a failed teardown", before)
				h.requirePeerUnchanged(t)
				if _, ok := h.manualRecord(t, removedOmnigentID); ok {
					t.Fatal("a failed teardown recorded manual steps")
				}
				if err := h.verify(); err == nil {
					t.Fatal("VerifyClean passed after a failed teardown")
				}
			}
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := h.teardown(t); err != nil {
				t.Fatalf("retry: %v", err)
			}
			h.requireDone(t)
			requireRemovedSnapshot(t, "retry", map[string]string{h.configPath: omnigentOperatorConfig, h.pthPath: removedMissing})
		})
	}
}

// --- OpenHands ---

const openHandsOperatorHooks = `{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/audit-hook"}]}]}`

type openHandsHarness struct {
	*removedHarness
	hooksPath, script string
	// noScript: a finished cleanup leaves no hook script (the user deleted
	// it), so there is no tombstone either.
	noScript bool
}

func newOpenHandsHarness(t *testing.T, configHome bool) *openHandsHarness {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("OpenHands was never set up on Windows")
	}
	h := &openHandsHarness{removedHarness: newRemovedHarness(t)}
	h.hooksPath = filepath.Join(h.home, ".openhands", "hooks.json")
	if configHome {
		h.opts.ConfigHome = filepath.Join(t.TempDir(), "openhands-home")
		h.hooksPath = filepath.Join(h.opts.ConfigHome, "hooks.json")
	}
	h.script = filepath.Join(h.dataDir, "hooks", removedOpenHandsHookScript)
	writeRemovedFixture(t, h.script, "#!/bin/sh\n# defenseclaw-managed-hook v1\n", 0o700)
	h.recordScript(t)
	writeRemovedFixture(t, filepath.Join(h.dataDir, "hooks", ".hookcfg.openhands"), "DEFENSECLAW_CONNECTOR=openhands\n", 0o600)
	writeRemovedFixture(t, filepath.Join(h.dataDir, "hooks", ".otlp-openhands.token"), strings.Repeat("a", 64)+"\n", 0o600)
	if _, err := EnsureHookAPIToken(h.dataDir, removedOpenHandsID); err != nil {
		t.Fatal(err)
	}
	return h
}

// recordScript saves what an older setup saved for its hook script: its
// digest in the hook contract lock.
func (h *openHandsHarness) recordScript(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(h.script)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveHookContractLockEntry(h.dataDir, HookContractLockEntry{
		Connector:         removedOpenHandsID,
		HookScriptDigests: map[string]string{removedOpenHandsHookScript: "sha256:" + sha256Hex(data)},
	}); err != nil {
		t.Fatal(err)
	}
}

// hooksDoc renders the hooks.json an older release wrote.
func (h *openHandsHarness) hooksDoc(t *testing.T) string {
	t.Helper()
	doc := map[string]interface{}{}
	if err := json.Unmarshal([]byte(openHandsOperatorHooks), &doc); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"pre_tool_use", "post_tool_use", "stop"} {
		group := map[string]interface{}{"matcher": "*", "hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": shellWord(h.script), "timeout": 60},
		}}
		existing, _ := doc[event].([]interface{})
		doc[event] = append(existing, group)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (h *openHandsHarness) setUp(t *testing.T, existed bool) {
	t.Helper()
	h.recordSetup(t, removedOpenHandsID, "config", h.hooksPath, openHandsOperatorHooks, existed, h.hooksDoc(t))
}

func (h *openHandsHarness) state(t *testing.T) map[string]string {
	t.Helper()
	return removedSnapshot(t, h.hooksPath, h.script,
		filepath.Join(h.dataDir, "hooks", ".hookcfg.openhands"),
		filepath.Join(h.dataDir, "hooks", ".otlp-openhands.token"),
		removedTokenFile(t, h.dataDir, removedOpenHandsID),
		managedFileBackupPath(h.dataDir, removedOpenHandsID, "config"))
}

func (h *openHandsHarness) teardown() error {
	conn, _ := RetiredConnector(removedOpenHandsID)
	return conn.Teardown(context.Background(), h.opts)
}

func (h *openHandsHarness) verify() error {
	conn, _ := RetiredConnector(removedOpenHandsID)
	return conn.VerifyClean(h.opts)
}

func (h *openHandsHarness) requireDone(t *testing.T) {
	t.Helper()
	if err := h.verify(); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
	if data, err := os.ReadFile(h.hooksPath); err == nil && strings.Contains(string(data), h.script) {
		t.Fatalf("hooks.json still runs DefenseClaw's hook: %s", data)
	}
	if h.noScript {
		requireRemovedSnapshot(t, "teardown", map[string]string{h.script: removedMissing})
	} else if body, err := os.ReadFile(h.script); err != nil || !removedOpenHandsTombstone(body) {
		t.Fatalf("hook script is not the disabled tombstone: %q, %v", body, err)
	}
	for _, gone := range []string{
		filepath.Join(h.dataDir, "hooks", ".hookcfg.openhands"),
		filepath.Join(h.dataDir, "hooks", ".otlp-openhands.token"),
		managedFileBackupPath(h.dataDir, removedOpenHandsID, "config"),
		removedCleanupRecordPath(h.dataDir, removedOpenHandsID),
	} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s survived teardown: %v", gone, err)
		}
	}
	if token, err := LoadHookAPIToken(h.dataDir, removedOpenHandsID); err != nil || token != "" {
		t.Fatalf("openhands token = %q, %v; want revoked", token, err)
	}
	h.requirePeerUnchanged(t)
}

func TestRemovedOpenHandsTeardownUndoesByteIdenticalSetup(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configHome bool
		existed    bool
		want       string
	}{
		{"hooks.json existed", false, true, openHandsOperatorHooks},
		{"hooks.json created by setup", false, false, removedMissing},
		{"config home", true, true, openHandsOperatorHooks},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOpenHandsHarness(t, tc.configHome)
			h.setUp(t, tc.existed)
			if err := h.verify(); err == nil {
				t.Fatal("VerifyClean passed while hooks.json is as DefenseClaw wrote it")
			}
			for run := 1; run <= 2; run++ {
				if err := h.teardown(); err != nil {
					t.Fatalf("Teardown run %d: %v", run, err)
				}
				h.requireDone(t)
			}
			requireRemovedSnapshot(t, "teardown", map[string]string{h.hooksPath: tc.want})
			if h.notices.Len() != 0 {
				t.Fatalf("a clean teardown printed: %s", h.notices)
			}
		})
	}
}

// An OpenHands hooks file that is not as DefenseClaw wrote it and still runs
// its hook script (or cannot be read) is left alone, and so is everything
// else: the hook script stays as it is (no allow-all tombstone while a hook
// still runs it), the token stays, and one warning gives the step.
func TestRemovedOpenHandsTeardownLeavesUnprovableStateUntouched(t *testing.T) {
	for _, tc := range []struct {
		name  string
		drift func(t *testing.T, h *openHandsHarness)
	}{
		{"hooks.json edited", func(t *testing.T, h *openHandsHarness) {
			writeRemovedFixture(t, h.hooksPath, strings.TrimSuffix(h.hooksDoc(t), "}")+`,"session_start":[]}`, 0o600)
		}},
		{"hooks.json names the script through JSON escapes", func(t *testing.T, h *openHandsHarness) {
			command := strings.ReplaceAll(h.script, "/", `\u002f`)
			writeRemovedFixture(t, h.hooksPath, `{"stop":[{"matcher":"*","hooks":[{"type":"command","command":"`+command+`"}]}]}`, 0o600)
		}},
		{"hooks.json without a record", func(t *testing.T, h *openHandsHarness) {
			discardManagedFileBackup(h.dataDir, removedOpenHandsID, "config")
		}},
		{"hooks.json is not valid JSON", func(t *testing.T, h *openHandsHarness) {
			writeRemovedFixture(t, h.hooksPath, `{"stop": [`, 0o600)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOpenHandsHarness(t, false)
			h.setUp(t, true)
			tc.drift(t, h)
			before := h.state(t)
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown = %v, want the state left for manual cleanup", err)
			}
			requireRemovedSnapshot(t, "a teardown that cannot prove ownership", before)
			h.requirePeerUnchanged(t)
			if got := strings.Count(h.notices.String(), "WARNING"); got != 1 || !strings.Contains(h.notices.String(), h.hooksPath) {
				t.Fatalf("printed %d warnings, want one naming %s:\n%s", got, h.hooksPath, h.notices)
			}
			if record, ok := h.manualRecord(t, removedOpenHandsID); !ok || !record.lists(h.hooksPath) {
				t.Fatalf("manual cleanup record = %+v, %v", record, ok)
			}
			if err := h.verify(); err != nil {
				t.Fatalf("VerifyClean with the steps recorded: %v", err)
			}

			writeRemovedFixture(t, h.hooksPath, openHandsOperatorHooks, 0o600)
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown after the manual step: %v", err)
			}
			h.requireDone(t)
		})
	}
}

func TestRemovedOpenHandsFailedCleanupLeavesNoPartialState(t *testing.T) {
	skipWhereModesDoNotBind(t)
	h := newOpenHandsHarness(t, false)
	h.setUp(t, true)
	before := h.state(t)
	dir := filepath.Dir(h.hooksPath)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := h.teardown(); err == nil {
		t.Fatal("Teardown succeeded with a read-only hooks directory")
	}
	requireRemovedSnapshot(t, "a failed teardown", before)
	if err := h.verify(); err == nil {
		t.Fatal("VerifyClean passed after a failed teardown")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := h.teardown(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	h.requireDone(t)
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
		filepath.Join(dataDir, removedCleanupDir),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("teardown created %s: %v", path, err)
		}
	}
}

// --- Review fixes (loop round 2) ---

// A saved copy that names DefenseClaw is put back without DefenseClaw's part
// when the file is DefenseClaw's by name: a policy module the user had before
// setup (no DefenseClaw marker) comes back byte for byte, and a saved .pth
// keeps every user line (any line ending, comments) and loses only
// DefenseClaw's line. A module the user wrote since setup is left alone.
func TestRemovedOmnigentTeardownKeepsUserModuleAndImportPaths(t *testing.T) {
	const userModule = "def check(event):\n    return None\n"
	for _, tc := range []struct {
		name       string
		setup      omnigentSetup
		pth        func(hookDir string) string // the saved .pth ("" = none)
		edit       func(t *testing.T, h *omnigentHarness)
		wantPth    func(hookDir string) string
		keptModule string
	}{
		{name: "saved module is the user's", setup: omnigentSetup{config: omnigentOperatorConfig, module: userModule}, keptModule: userModule},
		{
			name: "user rewrote the module after setup", setup: omnigentSetup{config: omnigentOperatorConfig},
			edit: func(t *testing.T, h *omnigentHarness) {
				writeRemovedFixture(t, h.modulePath, userModule, 0o600)
			},
			keptModule: userModule,
		},
		{
			name: "saved .pth holds a user line and DefenseClaw's", setup: omnigentSetup{config: omnigentOperatorConfig},
			pth:     func(d string) string { return "/opt/user-site\n" + d + "\n" },
			wantPth: func(string) string { return "/opt/user-site\n" },
		},
		{
			name: "saved .pth with CRLF and a comment", setup: omnigentSetup{config: omnigentOperatorConfig},
			pth:     func(d string) string { return "/opt/user-site\r\n" + d + "\r\n# keep me\r\n" },
			wantPth: func(string) string { return "/opt/user-site\r\n# keep me\r\n" },
		},
		{
			name: "saved .pth with DefenseClaw's line padded and last", setup: omnigentSetup{config: omnigentOperatorConfig},
			pth:     func(d string) string { return "/opt/a\nimport site\n  " + d + "  " },
			wantPth: func(string) string { return "/opt/a\nimport site\n" },
		},
		{
			name: "saved .pth with only DefenseClaw's line", setup: omnigentSetup{config: omnigentOperatorConfig},
			pth:     func(d string) string { return "\n" + d + "\n\n" },
			wantPth: func(string) string { return removedMissing },
		},
		{
			name: "saved module and .pth both hold user content", setup: omnigentSetup{config: omnigentOperatorConfig, module: userModule},
			pth:        func(d string) string { return d + "\n/opt/user-site\n" },
			wantPth:    func(string) string { return "/opt/user-site\n" },
			keptModule: userModule,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOmnigentHarness(t, false)
			if tc.pth != nil {
				tc.setup.pth = tc.pth(h.hookDir)
			}
			h.setUp(t, tc.setup)
			if tc.edit != nil {
				tc.edit(t, h)
			}
			h.keptModule = tc.keptModule
			for run := 1; run <= 2; run++ {
				if err := h.teardown(t); err != nil {
					t.Fatalf("Teardown run %d: %v", run, err)
				}
				h.requireDone(t)
			}
			want := map[string]string{h.configPath: omnigentOperatorConfig, h.pthPath: removedMissing}
			if tc.wantPth != nil {
				want[h.pthPath] = tc.wantPth(h.hookDir)
			}
			requireRemovedSnapshot(t, "teardown", want)
			if h.notices.Len() != 0 {
				t.Fatalf("a clean teardown printed: %s", h.notices)
			}
		})
	}
}

// A hook script DefenseClaw cannot prove it wrote (a link to another script,
// an edited script, no digest, not a file) stops the whole cleanup: hooks.json,
// the script and a link's target stay byte for byte and the step is recorded.
// Once the user deletes the script, the next teardown restores hooks.json and
// writes no tombstone. A script that is already a tombstone needs no record.
func TestRemovedOpenHandsTeardownLeavesForeignHookScript(t *testing.T) {
	const userScript = "#!/bin/sh\nexec /usr/local/bin/my-hook \"$@\"\n"
	for _, tc := range []struct {
		name  string
		drift func(t *testing.T, h *openHandsHarness) (extra string)
	}{
		{"script is a link to another script", func(t *testing.T, h *openHandsHarness) string {
			target := filepath.Join(t.TempDir(), "my-hook.sh")
			writeRemovedFixture(t, target, userScript, 0o700)
			if err := os.Remove(h.script); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, h.script); err != nil {
				t.Fatal(err)
			}
			return target
		}},
		{"script is a link to a missing file", func(t *testing.T, h *openHandsHarness) string {
			target := filepath.Join(t.TempDir(), "gone.sh")
			if err := os.Remove(h.script); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, h.script); err != nil {
				t.Fatal(err)
			}
			return target
		}},
		{"script edited", func(t *testing.T, h *openHandsHarness) string {
			writeRemovedFixture(t, h.script, "#!/bin/sh\n# defenseclaw-managed-hook v1\n# my tweak\n", 0o700)
			return ""
		}},
		{"script without a digest", func(t *testing.T, h *openHandsHarness) string {
			if err := ClearHookContractLockEntry(h.dataDir, removedOpenHandsID); err != nil {
				t.Fatal(err)
			}
			return ""
		}},
		{"script is a directory", func(t *testing.T, h *openHandsHarness) string {
			if err := os.Remove(h.script); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(h.script, 0o700); err != nil {
				t.Fatal(err)
			}
			return ""
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOpenHandsHarness(t, false)
			h.setUp(t, true)
			extra := tc.drift(t, h)
			paths := []string{h.hooksPath, filepath.Join(h.dataDir, "hooks", ".hookcfg.openhands"),
				removedTokenFile(t, h.dataDir, removedOpenHandsID), managedFileBackupPath(h.dataDir, removedOpenHandsID, "config")}
			if info, err := os.Lstat(h.script); err == nil && !info.IsDir() {
				paths = append(paths, h.script)
			}
			if extra != "" {
				paths = append(paths, extra)
			}
			before := removedSnapshot(t, paths...)
			for run := 1; run <= 2; run++ {
				h.notices.Reset()
				if err := h.teardown(); err != nil {
					t.Fatalf("Teardown run %d = %v, want the state left for manual cleanup", run, err)
				}
				requireRemovedSnapshot(t, "a teardown that cannot prove the hook script is DefenseClaw's", before)
				h.requirePeerUnchanged(t)
				if got := strings.Count(h.notices.String(), "WARNING"); got != 1 || !strings.Contains(h.notices.String(), h.script) {
					t.Fatalf("run %d printed %d warnings, want one naming %s:\n%s", run, got, h.script, h.notices)
				}
				if record, ok := h.manualRecord(t, removedOpenHandsID); !ok || !record.lists(h.script) || record.lists(h.hooksPath) {
					t.Fatalf("manual cleanup record = %+v, %v; want only the script", record, ok)
				}
				if err := h.verify(); err != nil {
					t.Fatalf("VerifyClean with the steps recorded: %v", err)
				}
			}
			if err := os.RemoveAll(h.script); err != nil {
				t.Fatal(err)
			}
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown after the manual step: %v", err)
			}
			h.noScript = true
			h.requireDone(t)
			requireRemovedSnapshot(t, "teardown", map[string]string{h.hooksPath: openHandsOperatorHooks})
			if extra != "" {
				requireRemovedSnapshot(t, "teardown", map[string]string{extra: before[extra]})
			}
		})
	}
	for _, label := range []string{"OpenHands", "openhands"} {
		t.Run("script is the tombstone "+label+" teardown wrote", func(t *testing.T) {
			h := newOpenHandsHarness(t, false)
			h.setUp(t, true)
			writeRemovedFixture(t, h.script, disabledHookTombstone(label), 0o700)
			if err := ClearHookContractLockEntry(h.dataDir, removedOpenHandsID); err != nil {
				t.Fatal(err)
			}
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			requireRemovedSnapshot(t, "teardown", map[string]string{h.script: disabledHookTombstone(label)})
			h.requireDone(t)
			if h.notices.Len() != 0 {
				t.Fatalf("a clean teardown printed: %s", h.notices)
			}
		})
	}
}

// failParentSyncOnce makes the next parent-directory sync after a rename into
// dir fail, with the new file already in place.
func failParentSyncOnce(t *testing.T, dir string) *int {
	t.Helper()
	failed := 0
	previous := atomicFileSyncParent
	atomicFileSyncParent = func(d string) error {
		if failed == 0 && sameManagedTargetPath(d, dir) {
			failed++
			return errors.New("injected: sync parent directory failed")
		}
		return previous(d)
	}
	t.Cleanup(func() { atomicFileSyncParent = previous })
	return &failed
}

// A change whose new bytes are in place when it fails (the parent directory
// sync after the rename) is rolled back with the changes before it, for
// every file a removed connector's cleanup writes: nothing is left half
// cleaned, and the retry finishes.
func TestRemovedCleanupRollsBackAWriteThatFailedAfterItsRename(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the parent directory is synced only on Linux and macOS")
	}
	for _, tc := range []struct {
		name string
		dir  func(h *omnigentHarness) string
	}{
		{"config.yaml", func(h *omnigentHarness) string { return filepath.Dir(h.configPath) }},
		{".pth", func(h *omnigentHarness) string { return filepath.Dir(h.pthPath) }},
		{"module", func(h *omnigentHarness) string { return h.hookDir }},
	} {
		t.Run("omnigent "+tc.name, func(t *testing.T) {
			h := newOmnigentHarness(t, false)
			const userModule = "def check(event):\n    return None\n"
			h.setUp(t, omnigentSetup{config: omnigentOperatorConfig, pth: "/opt/user-site\n", module: userModule})
			before := h.state(t)
			failed := failParentSyncOnce(t, tc.dir(h))
			if err := h.teardown(t); err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("Teardown = %v, want the injected failure", err)
			}
			if *failed != 1 {
				t.Fatalf("the injected failure ran %d times", *failed)
			}
			requireRemovedSnapshot(t, "a teardown whose write failed after its rename", before)
			h.requirePeerUnchanged(t)
			if err := h.verify(); err == nil {
				t.Fatal("VerifyClean passed after a failed teardown")
			}
			if err := h.teardown(t); err != nil {
				t.Fatalf("retry: %v", err)
			}
			h.keptModule = userModule
			h.requireDone(t)
			requireRemovedSnapshot(t, "retry", map[string]string{h.configPath: omnigentOperatorConfig, h.pthPath: "/opt/user-site\n"})
		})
	}
	for _, tc := range []struct {
		name string
		dir  func(h *openHandsHarness) string
	}{
		{"hooks.json", func(h *openHandsHarness) string { return filepath.Dir(h.hooksPath) }},
		{"tombstone", func(h *openHandsHarness) string { return filepath.Dir(h.script) }},
	} {
		t.Run("openhands "+tc.name, func(t *testing.T) {
			h := newOpenHandsHarness(t, false)
			h.setUp(t, true)
			before := h.state(t)
			failParentSyncOnce(t, tc.dir(h))
			if err := h.teardown(); err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("Teardown = %v, want the injected failure", err)
			}
			requireRemovedSnapshot(t, "a teardown whose write failed after its rename", before)
			if err := h.verify(); err == nil {
				t.Fatal("VerifyClean passed after a failed teardown")
			}
			if err := h.teardown(); err != nil {
				t.Fatalf("retry: %v", err)
			}
			h.requireDone(t)
		})
	}
}

// The writer removed connectors use never writes through a link: it refuses
// a link (or anything not a regular file) and leaves its target alone, and it
// replaces or creates a regular file.
func TestAtomicWriteFileNoFollowNeverWritesThroughALink(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	writeRemovedFixture(t, regular, "old", 0o600)
	if err := atomicWriteFileNoFollow(regular, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(dir, "created")
	if err := atomicWriteFileNoFollow(created, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireRemovedSnapshot(t, "atomicWriteFileNoFollow", map[string]string{regular: "new", created: "new"})
	if err := atomicWriteFileNoFollow(dir, []byte("new"), 0o600); err == nil {
		t.Fatal("wrote over a directory")
	}
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	target := filepath.Join(t.TempDir(), "target")
	writeRemovedFixture(t, target, "theirs", 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFileNoFollow(link, []byte("new"), 0o600); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("atomicWriteFileNoFollow(link) = %v, want a refusal", err)
	}
	requireRemovedSnapshot(t, "a refused write", map[string]string{target: "theirs", link: "symlink:" + target})
}

// The manual cleanup record is never written through a link either.
func TestRemovedManualCleanupRecordIsNotWrittenThroughALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	h := newOmnigentHarness(t, false)
	h.setUp(t, omnigentSetup{config: omnigentOperatorConfig})
	writeRemovedFixture(t, h.configPath, omnigentPatchedConfig+"model: local\n", 0o600)
	target := filepath.Join(t.TempDir(), "theirs.json")
	writeRemovedFixture(t, target, "theirs", 0o600)
	record := removedCleanupRecordPath(h.dataDir, removedOmnigentID)
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, record); err != nil {
		t.Fatal(err)
	}
	before := h.state(t)
	if err := h.teardown(t); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Teardown = %v, want the linked record refused", err)
	}
	requireRemovedSnapshot(t, "a refused record write", map[string]string{target: "theirs", record: "symlink:" + target})
	requireRemovedSnapshot(t, "a refused record write", before)
}
