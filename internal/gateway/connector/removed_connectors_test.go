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
	"os/exec"
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
	// The home is not named after the test, as t.TempDir is: the OpenHands
	// tests run hook commands under it, and a blank, a quote or a # from a
	// test's name would change how the shell reads them.
	home, err := os.MkdirTemp("", "removed-home-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	restoreHome, err := BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	t.Setenv("OMNIGENT_CONFIG_HOME", "")
	t.Setenv("OMNIGENT_CONFIG", "")
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
	// keptModule is the module a finished cleanup leaves ("" = none);
	// keptPth, the .pth ("" = none naming the hook directory).
	keptModule, keptPth string
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
	if h.keptPth != "" {
		requireRemovedSnapshot(t, "teardown", map[string]string{h.pthPath: h.keptPth})
	} else if data, err := os.ReadFile(h.pthPath); err == nil && strings.Contains(string(data), h.hookDir) {
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
		{name: "saved module is what setup wrote (GAP-1926)", setup: omnigentSetup{config: omnigentOperatorConfig, module: omnigentModule}, wantConfig: omnigentOperatorConfig, wantPth: removedMissing},
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
		// savedPth is the .pth setup found, given the hook directory.
		savedPth func(hookDir string) string
		// drift makes the unprovable state and returns the file the
		// warning must name; fix does the recorded step.
		drift func(t *testing.T, h *omnigentHarness) string
		fix   func(t *testing.T, h *omnigentHarness)
	}{
		// Review loop round 3: a saved module or .pth that names DefenseClaw
		// was dropped (the module) or put back without DefenseClaw's line
		// (the .pth) although it may be the user's. Now only a copy that is
		// byte for byte what setup wrote is dropped; any other is left.
		{
			name: "saved module names DefenseClaw but is not what setup wrote", setup: omnigentSetup{config: omnigentOperatorConfig, module: "# defenseclaw-managed-policy v1\n# older\n"},
			drift: func(t *testing.T, h *omnigentHarness) string { return h.modulePath },
			fix:   func(t *testing.T, h *omnigentHarness) { _ = os.Remove(h.modulePath) },
		},
		{
			name: "saved module is user code that quotes the marker", setup: omnigentSetup{config: omnigentOperatorConfig, module: "def check(event):\n    return None\n# copied from # defenseclaw-managed-policy v1\n"},
			drift: func(t *testing.T, h *omnigentHarness) string { return h.modulePath },
			fix:   func(t *testing.T, h *omnigentHarness) { _ = os.Remove(h.modulePath) },
		},
		{
			name: "saved .pth names the hook directory next to a user line", setup: omnigentSetup{config: omnigentOperatorConfig},
			savedPth: func(d string) string { return "/opt/user-site\n" + d + "\n" },
			drift:    func(t *testing.T, h *omnigentHarness) string { return h.pthPath },
			fix:      func(t *testing.T, h *omnigentHarness) { writeRemovedFixture(t, h.pthPath, "/opt/user-site\n", 0o600) },
		},
		{
			name: "saved .pth with CRLF and a comment names the hook directory", setup: omnigentSetup{config: omnigentOperatorConfig},
			savedPth: func(d string) string { return "/opt/user-site\r\n" + d + "\r\n# keep me\r\n" },
			drift:    func(t *testing.T, h *omnigentHarness) string { return h.pthPath },
			fix:      func(t *testing.T, h *omnigentHarness) { _ = os.Remove(h.pthPath) },
		},
		{
			name: "saved .pth with only the hook directory, padded", setup: omnigentSetup{config: omnigentOperatorConfig},
			savedPth: func(d string) string { return "\n  " + d + "  \n\n" },
			drift:    func(t *testing.T, h *omnigentHarness) string { return h.pthPath },
			fix:      func(t *testing.T, h *omnigentHarness) { _ = os.Remove(h.pthPath) },
		},
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
			if tc.savedPth != nil {
				tc.setup.pth = tc.savedPth(h.hookDir)
			}
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
					// A saved copy left for the user says where it is.
					if strings.Contains(item.Reason, "saved before its setup") && !strings.Contains(item.Step, "pristine_bytes") {
						t.Fatalf("manual step for a saved copy does not say where it is: %+v", item)
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
	// What the hook writer of 0.8.10 through 1.0.3 wrote.
	writeRemovedFixture(t, filepath.Join(h.dataDir, "hooks", ".hookcfg.openhands"), removedOpenHandsRuntimeRecord("closed"), 0o600)
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
	return h.hooksDocOver(t, openHandsOperatorHooks)
}

// hooksDocOver renders the hooks.json an older release wrote over saved, the
// hooks.json its setup found.
func (h *openHandsHarness) hooksDocOver(t *testing.T, saved string) string {
	t.Helper()
	doc := map[string]interface{}{}
	if err := json.Unmarshal([]byte(saved), &doc); err != nil {
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

// An OpenHands hooks file that is not as DefenseClaw wrote it and still names
// its hook script (or cannot be read) is left alone, and so is everything
// else: the hook script stays as it is, the token stays, and one warning
// gives the step.
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

// A hooks file the hook contract lock says setup wrote (a workspace's
// .openhands/hooks.json) is checked even with no backup record for it: while
// it runs the script, nothing changes and the script is not the tombstone.
func TestRemovedOpenHandsTeardownChecksTheHooksFilesTheLockNames(t *testing.T) {
	// Review fixes (loop round 1): a relative path in the lock was skipped;
	// it is read from the working directory now.
	for _, relative := range []bool{false, true} {
		t.Run(map[bool]string{false: "absolute", true: "relative"}[relative], func(t *testing.T) {
			h := newOpenHandsHarness(t, false)
			h.setUp(t, true)
			root := t.TempDir()
			workspace := filepath.Join(root, "repo", ".openhands", "hooks.json")
			named := workspace
			if relative {
				t.Chdir(root)
				named = filepath.Join("repo", ".openhands", "hooks.json")
			}
			writeRemovedFixture(t, workspace, `{"stop":[{"matcher":"*","hooks":[{"type":"command","command":"`+h.script+`"}]}]}`, 0o600)
			data, err := os.ReadFile(h.script)
			if err != nil {
				t.Fatal(err)
			}
			if err := SaveHookContractLockEntry(h.dataDir, HookContractLockEntry{
				Connector:         removedOpenHandsID,
				HookScriptDigests: map[string]string{removedOpenHandsHookScript: "sha256:" + sha256Hex(data)},
				Locations:         ConnectorLocations{HookConfigPaths: []string{h.hooksPath, named}},
			}); err != nil {
				t.Fatal(err)
			}
			before := h.state(t)
			before[workspace] = removedSnapshot(t, workspace)[workspace]
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown = %v, want the state left for manual cleanup", err)
			}
			requireRemovedSnapshot(t, "a teardown with a workspace hooks file that runs the script", before)
			if record, ok := h.manualRecord(t, removedOpenHandsID); !ok || !record.lists(workspace) {
				t.Fatalf("manual cleanup record = %+v, %v; want %s", record, ok, workspace)
			}
			writeRemovedFixture(t, workspace, `{}`, 0o600)
			h.notices.Reset()
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown after the manual step: %v", err)
			}
			h.requireDone(t)
			requireRemovedSnapshot(t, "teardown", map[string]string{h.hooksPath: openHandsOperatorHooks, workspace: `{}`})
		})
	}
}

// A changed hooks.json that provably runs nothing (gone, back to the copy
// setup found, or holding no command) lets the script become the tombstone
// with no warning.
func TestRemovedOpenHandsTeardownTombstonesWhenNoHookCanRunTheScript(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string // "" removes hooks.json
	}{
		{"hooks.json emptied", `{}`},
		{"only matchers left", `{"stop":[{"matcher":"*","hooks":[]}],"pre_tool_use":[]}`},
		{"blank command", `{"stop":[{"matcher":"*","hooks":[{"type":"command","command":"  "}]}]}`},
		{"hooks.json deleted", ""},
		{"hooks.json put back as setup found it", openHandsOperatorHooks},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOpenHandsHarness(t, false)
			h.setUp(t, true)
			if tc.body == "" {
				if err := os.Remove(h.hooksPath); err != nil {
					t.Fatal(err)
				}
			} else {
				writeRemovedFixture(t, h.hooksPath, tc.body, 0o600)
			}
			want := removedSnapshot(t, h.hooksPath)
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if h.notices.Len() != 0 {
				t.Fatalf("a clean teardown printed: %s", h.notices)
			}
			h.requireDone(t)
			requireRemovedSnapshot(t, "teardown", want)
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

// --- Review fixes (loop rounds 2 and 3) ---

// A saved copy that does not name DefenseClaw goes back byte for byte, and so
// does a saved .pth that names the hook directory when the user's own policy
// module stays there: that module needs the line (review loop round 3). A
// module the user wrote since setup is left alone, and a saved copy that is
// exactly what setup wrote is dropped.
func TestRemovedOmnigentTeardownPutsSavedCopiesBackExactly(t *testing.T) {
	const userModule = "def check(event):\n    return None\n"
	for _, tc := range []struct {
		name       string
		setup      omnigentSetup
		pth        func(hookDir string) string // the saved .pth ("" = none)
		edit       func(t *testing.T, h *omnigentHarness)
		keptPth    func(hookDir string) string // what the .pth must hold after ("" = removed)
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
			name: "saved .pth holds only user lines", setup: omnigentSetup{config: omnigentOperatorConfig},
			pth:     func(string) string { return "/opt/user-site\r\nimport site\n" },
			keptPth: func(string) string { return "/opt/user-site\r\nimport site\n" },
		},
		{
			name: "saved .pth is what setup wrote (GAP-1926)", setup: omnigentSetup{config: omnigentOperatorConfig},
			pth: func(d string) string { return d + "\n" },
		},
		{
			name: "saved user module and the .pth line it needs", setup: omnigentSetup{config: omnigentOperatorConfig, module: userModule},
			pth:        func(d string) string { return d + "\n" },
			keptPth:    func(d string) string { return d + "\n" },
			keptModule: userModule,
		},
		{
			name: "saved user module and a .pth with its line among user lines", setup: omnigentSetup{config: omnigentOperatorConfig, module: userModule},
			pth:        func(d string) string { return "/opt/a\r\n  " + d + "\r\n# keep me" },
			keptPth:    func(d string) string { return "/opt/a\r\n  " + d + "\r\n# keep me" },
			keptModule: userModule,
		},
		{
			name: "user module written after setup keeps the saved .pth line", setup: omnigentSetup{config: omnigentOperatorConfig},
			pth: func(d string) string { return d + "\n/opt/user-site\n" },
			edit: func(t *testing.T, h *omnigentHarness) {
				writeRemovedFixture(t, h.modulePath, userModule, 0o600)
			},
			keptPth:    func(d string) string { return d + "\n/opt/user-site\n" },
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
			want := map[string]string{h.configPath: omnigentOperatorConfig, h.pthPath: removedMissing}
			if tc.keptPth != nil {
				want[h.pthPath] = tc.keptPth(h.hookDir)
				if strings.Contains(want[h.pthPath], h.hookDir) {
					h.keptPth = want[h.pthPath]
				}
			}
			for run := 1; run <= 2; run++ {
				if err := h.teardown(t); err != nil {
					t.Fatalf("Teardown run %d: %v", run, err)
				}
				h.requireDone(t)
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
// writes no tombstone. A tombstone that exits 0, which a 1.0.x teardown (or
// an earlier 1.0.4 build) wrote, needs no record: its bytes are DefenseClaw's,
// and it becomes the tombstone that blocks.
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
		t.Run("script is the tombstone that exits 0 a "+label+" teardown wrote", func(t *testing.T) {
			h := newOpenHandsHarness(t, false)
			// The saved hooks.json runs the script through a link.
			link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "oh-audit"))
			saved := openHandsHooksRunning(t, link)
			h.setUpOver(t, saved, false)
			writeRemovedFixture(t, h.script, disabledHookTombstone(label), 0o700)
			if err := ClearHookContractLockEntry(h.dataDir, removedOpenHandsID); err != nil {
				t.Fatal(err)
			}
			for run := 1; run <= 2; run++ {
				if err := h.teardown(); err != nil {
					t.Fatalf("Teardown run %d: %v", run, err)
				}
				h.requireDone(t)
			}
			if h.notices.Len() != 0 {
				t.Fatalf("a clean teardown printed: %s", h.notices)
			}
			requireRemovedSnapshot(t, "teardown", map[string]string{h.hooksPath: saved})
			requireOpenHandsDeny(t, link, runOpenHandsHook(t, h, link, nil))
		})
	}
}

// failParentSyncOnce makes the next parent-directory sync after a rename into
// dir fail, with the new file already in place.
func failParentSyncOnce(t *testing.T, dir string) *int {
	t.Helper()
	return failParentSyncOnceWhile(t, dir, nil)
}

// failParentSyncOnceWhile is failParentSyncOnce that first runs during (when
// set): another process changing files while the cleanup runs.
func failParentSyncOnceWhile(t *testing.T, dir string, during func()) *int {
	t.Helper()
	failed := 0
	previous := atomicFileSyncParent
	atomicFileSyncParent = func(d string) error {
		if failed == 0 && sameManagedTargetPath(d, dir) {
			failed++
			if during != nil {
				during()
			}
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

// --- Review fixes (loop round 4) ---

// openHandsHooksRunning renders a hooks.json with one hook per command.
func openHandsHooksRunning(t *testing.T, commands ...string) string {
	t.Helper()
	hooks := make([]interface{}, 0, len(commands))
	for _, command := range commands {
		hooks = append(hooks, map[string]interface{}{"type": "command", "command": command, "timeout": 30})
	}
	data, err := json.Marshal(map[string]interface{}{"pre_tool_use": []interface{}{
		map[string]interface{}{"matcher": "*", "hooks": hooks},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// linkRemovedScript makes path a symlink to the OpenHands hook script.
func linkRemovedScript(t *testing.T, h *openHandsHarness, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(h.script, path); err != nil {
		t.Fatal(err)
	}
	return path
}

// setUpOver does what an older OpenHands setup did over saved, the
// hooks.json it found; back puts hooks.json back to saved afterwards, as a
// user who undid DefenseClaw's hooks by hand would.
func (h *openHandsHarness) setUpOver(t *testing.T, saved string, back bool) {
	t.Helper()
	h.recordSetup(t, removedOpenHandsID, "config", h.hooksPath, saved, true, h.hooksDocOver(t, saved))
	if back {
		writeRemovedFixture(t, h.hooksPath, saved, 0o600)
	}
}

// --- Review fixes (G-deadcode, the tombstone never allows) ---

// removedQuote quotes s as one shell word.
func removedQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// removedHookRun is what running an OpenHands hook command gave.
type removedHookRun struct {
	status         int
	stdout, stderr string
}

// runOpenHandsHook runs a hook command the way OpenHands runs one (sh -c), as
// the user (home, with ~/bin first on PATH, plus env), with a tool call on
// stdin.
func runOpenHandsHook(t *testing.T, h *openHandsHarness, command string, env []string) removedHookRun {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Dir = h.home
	cmd.Env = append([]string{"HOME=" + h.home, "PATH=" + filepath.Join(h.home, "bin") + ":/usr/bin:/bin", "SHELL=/bin/sh", "LC_ALL=C"}, env...)
	cmd.Stdin = strings.NewReader(`{"event":"pre_tool_use","tool_name":"bash","tool_input":{"command":"rm -rf ~"}}` + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	run := removedHookRun{}
	var exit *exec.ExitError
	switch err := cmd.Run(); {
	case errors.As(err, &exit):
		run.status = exit.ExitCode()
	case err != nil:
		t.Fatalf("run %q: %v", command, err)
	}
	run.stdout, run.stderr = stdout.String(), stderr.String()
	return run
}

// requireOpenHandsDeny checks that a hook run blocked the call: exit status 2,
// and a last line of output that is the deny decision with the message that
// says OpenHands support was removed and how to remove the hook.
func requireOpenHandsDeny(t *testing.T, what string, run removedHookRun) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(run.stdout), "\n")
	var reply struct{ Decision, Reason string }
	if run.status != 2 || json.Unmarshal([]byte(lines[len(lines)-1]), &reply) != nil || reply.Decision != "deny" ||
		!strings.Contains(reply.Reason, "OpenHands support was removed in DefenseClaw 1.0.4") ||
		!strings.Contains(reply.Reason, "remove every hook that runs "+removedOpenHandsHookScript+" from your OpenHands hooks.json") {
		t.Fatalf("%s: exit %d, stdout %q, stderr %q; want exit 2 and the deny decision with the removal message", what, run.status, run.stdout, run.stderr)
	}
}

// A hard link to the hook script keeps the old bytes when the tombstone
// replaces the file, so a hook that runs the link would not run the
// tombstone. Such a script, the one an older setup wrote or a tombstone that
// exits 0, is left for the user with hooks.json; once the link is gone the
// cleanup finishes and the script blocks.
func TestRemovedOpenHandsTeardownLeavesAHardLinkedScript(t *testing.T) {
	for _, tc := range []struct{ name, script string }{
		{name: "the script an older setup wrote"},
		{name: "a tombstone that exits 0", script: disabledHookTombstone(removedOpenHandsID)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOpenHandsHarness(t, false)
			if tc.script != "" {
				writeRemovedFixture(t, h.script, tc.script, 0o700)
			}
			hardLink := filepath.Join(h.home, "hooks-of-mine", "audit")
			if err := os.MkdirAll(filepath.Dir(hardLink), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(h.script, hardLink); err != nil {
				t.Fatal(err)
			}
			saved := openHandsHooksRunning(t, hardLink)
			h.setUpOver(t, saved, false)
			before := h.state(t)
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown = %v, want the state left for manual cleanup", err)
			}
			requireRemovedSnapshot(t, "a teardown with a hard-linked script", before)
			if notice := h.notices.String(); strings.Count(notice, "WARNING") != 1 || !strings.Contains(notice, h.script) || !strings.Contains(notice, "hard link") {
				t.Fatalf("notice = %q, want one warning naming %s and its hard link", notice, h.script)
			}
			if record, ok := h.manualRecord(t, removedOpenHandsID); !ok || !record.lists(h.script) {
				t.Fatalf("manual cleanup record = %+v, %v; want the script", record, ok)
			}
			if err := h.verify(); err != nil {
				t.Fatalf("VerifyClean with the steps recorded: %v", err)
			}
			if err := os.Remove(hardLink); err != nil {
				t.Fatal(err)
			}
			h.notices.Reset()
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown after the manual step: %v", err)
			}
			h.requireDone(t)
			requireRemovedSnapshot(t, "teardown", map[string]string{h.hooksPath: saved})
			requireOpenHandsDeny(t, h.script, runOpenHandsHook(t, h, removedQuote(h.script), nil))
		})
	}
}

// envSplitsWords reports whether this system's env takes -S.
func envSplitsWords() bool {
	return exec.Command("/usr/bin/env", "-S", "true").Run() == nil
}

// Review fixes (G-deadcode, class rule): the OpenHands tombstone exited 0, so
// any hook that still ran the script once the cleanup was done allowed every
// call; the check that tried to rule such hooks out kept missing some (a
// login shell under a name it did not know read a profile that ran the
// script). The tombstone now blocks every call, whatever runs it, with a
// message that says OpenHands support was removed and how to remove the hook.
func TestRemovedOpenHandsTombstoneBlocksUnderEveryShell(t *testing.T) {
	h := newOpenHandsHarness(t, false)
	h.setUp(t, true)
	if err := h.teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	h.requireDone(t)
	script := removedQuote(h.script)
	quoted := linkRemovedScript(t, h, filepath.Join(h.home, "my hooks", "openhands hook"))
	commands := []string{
		script,
		script + " --event pre_tool_use 30",
		removedQuote(quoted),
		`"` + quoted + `"`,
		"$HOME/.defenseclaw/hooks/" + removedOpenHandsHookScript,
		"~/.defenseclaw/hooks/" + removedOpenHandsHookScript,
		filepath.Join(h.dataDir, "hooks") + "//" + removedOpenHandsHookScript,
		"exec " + script,
		"/bin/true; " + script,
		". " + script,
		"/bin/sh " + script,
		"/bin/sh -e " + script,
		"/bin/sh -l " + script,
		"/bin/sh -x " + script,
		"/bin/sh < " + script,
		"/bin/sh -c " + removedQuote(script+" --audit"),
		"/bin/sh -c " + removedQuote(". "+script),
		"/usr/bin/env " + script,
		"/usr/bin/env -i " + script,
	}
	if envSplitsWords() {
		commands = append(commands, "/usr/bin/env -S "+removedQuote(script+" --audit"))
	}
	shells := 0
	for _, shell := range []string{"bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "busybox"} {
		path, err := exec.LookPath(shell)
		if err != nil {
			continue
		}
		shells++
		if shell == "busybox" {
			commands = append(commands, path+" sh "+script)
			continue
		}
		commands = append(commands, path+" "+script, path+" -l "+script)
	}
	if shells == 0 {
		t.Log("no shell but /bin/sh found")
	}
	for _, command := range commands {
		requireOpenHandsDeny(t, command, runOpenHandsHook(t, h, command, nil))
	}
}

// Every hook that still runs the script after the cleanup (one in the
// hooks.json the cleanup puts back, or in the user's own hooks.json) blocks
// the call with the removal message: the cleanup no longer tries to rule such
// hooks out. It puts hooks.json back, makes the script the tombstone and
// prints nothing.
func TestRemovedOpenHandsTombstoneBlocksEveryHookThatStillRunsIt(t *testing.T) {
	type hook func(t *testing.T, h *openHandsHarness) (command string, env []string)
	link := func(name string) hook {
		return func(t *testing.T, h *openHandsHarness) (string, []string) {
			return linkRemovedScript(t, h, filepath.Join(h.home, name)), nil
		}
	}
	// wrapper makes ~/tools/audit with text and returns the command that runs it.
	wrapper := func(t *testing.T, h *openHandsHarness, text string) string {
		t.Helper()
		path := filepath.Join(h.home, "tools", "audit")
		writeRemovedFixture(t, path, text, 0o700)
		return path
	}
	// startup makes the startup file name (under home) exec a link to the
	// script, and a plain script for the command to run.
	startup := func(name, command string) hook {
		return func(t *testing.T, h *openHandsHarness) (string, []string) {
			relay := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "relay"))
			writeRemovedFixture(t, filepath.Join(h.home, name), "exec "+relay+"\n", 0o600)
			return command + " " + wrapper(t, h, "exit 0\n"), nil
		}
	}
	cases := []struct {
		name string
		hook hook
		// needs is a program the case runs ("" for none).
		needs string
	}{
		{name: "a symlink", hook: link("hooks-of-mine/audit")},
		{name: "a quoted symlink with a blank", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			return removedQuote(linkRemovedScript(t, h, filepath.Join(h.home, "my hooks", "audit"))), nil
		}},
		{name: "$HOME", hook: func(*testing.T, *openHandsHarness) (string, []string) {
			return "$HOME/.defenseclaw/hooks/" + removedOpenHandsHookScript, nil
		}},
		{name: "~", hook: func(*testing.T, *openHandsHarness) (string, []string) {
			return "~/.defenseclaw/hooks/" + removedOpenHandsHookScript, nil
		}},
		{name: "a doubled path", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			return filepath.Join(h.dataDir, "hooks") + "//" + removedOpenHandsHookScript, nil
		}},
		{name: "a command found on PATH", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			linkRemovedScript(t, h, filepath.Join(h.home, "bin", "oh-audit"))
			return "oh-audit --audit", nil
		}},
		{name: "a command that is a number found on PATH", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			linkRemovedScript(t, h, filepath.Join(h.home, "bin", "30"))
			return "30", nil
		}},
		{name: "an interpreter that runs a symlink", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			return "/bin/sh " + linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run")) + " --audit 30", nil
		}},
		{name: "sh -c", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			return "/bin/sh -c " + removedQuote(linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run"))+" --audit"), nil
		}},
		{name: "sh -c that sources a symlink", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			return "/bin/sh -c " + removedQuote(". "+linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run"))), nil
		}},
		{name: "a shell list", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			return "/bin/true; " + linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run")), nil
		}},
		{name: "env -S that runs a command found on PATH", needs: "env -S", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			linkRemovedScript(t, h, filepath.Join(h.home, "bin", "relay"))
			return "/usr/bin/env -Srelay", nil
		}},
		{name: "env -S with its command line in the next word", needs: "env -S", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			linkRemovedScript(t, h, filepath.Join(h.home, "bin", "relay"))
			return "/usr/bin/env -S 'relay --audit'", nil
		}},
		{name: "a wrapper that names the script under HOME", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			return wrapper(t, h, "#!/bin/sh\nexec \"$HOME/.defenseclaw/hooks/openhands-hook.sh\" \"$@\"\n") + " --audit", nil
		}},
		{name: "a wrapper's wrapper", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			inner := filepath.Join(h.home, "lib", "inner.sh")
			writeRemovedFixture(t, inner, "#!/bin/sh\nexec \"$HOME/.defenseclaw/hooks/openhands-hook.sh\"\n", 0o700)
			return wrapper(t, h, "#!/bin/sh\nexec "+inner+"\n"), nil
		}},
		{name: "a wrapper that runs a quoted path with a blank", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			relay := linkRemovedScript(t, h, filepath.Join(h.home, "audit dir", "relay"))
			return wrapper(t, h, "#!/bin/sh\nexec \""+relay+"\" \"$@\"\n"), nil
		}},
		{name: "a wrapper that puts a directory on PATH", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			relay := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "oh-relay"))
			return wrapper(t, h, "#!/bin/sh\nPATH=/usr/bin:/bin:"+filepath.Dir(relay)+"\nexport PATH\nexec oh-relay \"$@\"\n"), nil
		}},
		{name: "a Python wrapper that builds the path at run time", needs: "/usr/bin/python3", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			linkRemovedScript(t, h, filepath.Join(h.home, "audit dir", "relay"))
			return wrapper(t, h, "#!/usr/bin/python3\nimport os, sys\nos.execv(os.path.join(os.environ[\"HOME\"], \"audit dir\", \"relay\"), sys.argv)\n"), nil
		}},
		{name: "a shell script with a NUL byte that sh runs", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			relay := linkRemovedScript(t, h, filepath.Join(h.home, "relay"))
			return "/bin/sh " + wrapper(t, h, "#!/bin/sh\n: \x00\nexec "+relay+" \"$@\"\n"), nil
		}},
		{name: "a shell script with a NUL byte run directly", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			relay := linkRemovedScript(t, h, filepath.Join(h.home, "relay"))
			return wrapper(t, h, "#!/bin/sh\n: \x00\nexec "+relay+" \"$@\"\n"), nil
		}},
		{name: "a login shell that runs a symlink", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			return "/bin/sh -l " + linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run")), nil
		}},
		{name: "a login shell whose profile runs a symlink", hook: startup(".profile", "/bin/sh -l")},
		{name: "a #! line that passes the shell -l", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			relay := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "relay"))
			writeRemovedFixture(t, filepath.Join(h.home, ".profile"), "exec "+relay+"\n", 0o600)
			return wrapper(t, h, "#!/bin/sh -l\nexit 0\n"), nil
		}},
		{name: "a login shell under a name the system does not know", needs: "/bin/bash", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			// The case the reviewer found: a copy of bash read
			// ~/.bash_profile, which ran a link to the script.
			bash, err := os.ReadFile("/bin/bash")
			if err != nil {
				t.Fatal(err)
			}
			shell := filepath.Join(h.home, "opt", "bin", "bash-static")
			writeRemovedFixture(t, shell, string(bash), 0o755)
			return startup(".bash_profile", shell+" -l")(t, h)
		}},
		{name: "bash with BASH_ENV set", needs: "/bin/bash", hook: func(t *testing.T, h *openHandsHarness) (string, []string) {
			command, env := startup(".bashenv", "/bin/bash")(t, h)
			return command, append(env, "BASH_ENV="+filepath.Join(h.home, ".bashenv"))
		}},
	}
	for _, tc := range cases {
		for _, back := range []bool{false, true} {
			mode := "put back by the cleanup"
			if back {
				mode = "the user's own hooks.json"
			}
			t.Run(tc.name+", "+mode, func(t *testing.T) {
				switch {
				case tc.needs == "env -S":
					if !envSplitsWords() {
						t.Skip("env does not take -S here")
					}
				case tc.needs != "":
					if _, err := os.Stat(tc.needs); err != nil {
						t.Skipf("no %s here", tc.needs)
					}
				}
				h := newOpenHandsHarness(t, false)
				command, env := tc.hook(t, h)
				saved := openHandsHooksRunning(t, "/usr/local/bin/audit-hook", command)
				h.setUpOver(t, saved, back)
				for run := 1; run <= 2; run++ {
					if err := h.teardown(); err != nil {
						t.Fatalf("Teardown run %d: %v", run, err)
					}
					h.requireDone(t)
				}
				if h.notices.Len() != 0 {
					t.Fatalf("teardown printed: %s", h.notices)
				}
				requireRemovedSnapshot(t, "teardown", map[string]string{h.hooksPath: saved})
				requireOpenHandsDeny(t, command, runOpenHandsHook(t, h, command, env))
			})
		}
	}
}

// Review loop round 4: OmniGent teardown did not read the config that
// OMNIGENT_CONFIG selects (OmniGent reads it before any config home), and
// with a config home given it read no other config. Every config OmniGent
// may read is checked now, whichever is given: one that still names the
// module keeps every file in place until the user removes the entries.
func TestRemovedOmnigentTeardownChecksEveryConfigOmniGentMayRead(t *testing.T) {
	explicit := func(env string, parts ...string) func(t *testing.T, h *omnigentHarness) string {
		return func(t *testing.T, h *omnigentHarness) string {
			t.Setenv("OMNIGENT_CONFIG", env)
			return filepath.Join(append([]string{h.home}, parts...)...)
		}
	}
	for _, tc := range []struct {
		name       string
		configHome bool
		// active selects the config OmniGent reads and returns its path.
		active func(t *testing.T, h *omnigentHarness) string
	}{
		{"OMNIGENT_CONFIG", false, func(t *testing.T, h *omnigentHarness) string {
			path := filepath.Join(h.home, "policies", "active.yaml")
			t.Setenv("OMNIGENT_CONFIG", path)
			return path
		}},
		{"OMNIGENT_CONFIG with a config home", true, func(t *testing.T, h *omnigentHarness) string {
			path := filepath.Join(h.home, "policies", "active.yaml")
			t.Setenv("OMNIGENT_CONFIG", "  "+path+"  ")
			return path
		}},
		{"OMNIGENT_CONFIG under ~", false, explicit("~/policies/active.yaml", "policies", "active.yaml")},
		{"relative OMNIGENT_CONFIG", false, func(t *testing.T, h *omnigentHarness) string {
			t.Chdir(h.home)
			return explicit(filepath.Join("policies", "active.yml"), "policies", "active.yml")(t, h)
		}},
		{"OMNIGENT_CONFIG_HOME with a config home", true, func(t *testing.T, h *omnigentHarness) string {
			other := filepath.Join(h.home, "omnigent-env")
			t.Setenv("OMNIGENT_CONFIG_HOME", other)
			return filepath.Join(other, "config.yaml")
		}},
		{"the default config with a config home", true, func(t *testing.T, h *omnigentHarness) string {
			return filepath.Join(h.home, ".omnigent", "config.yaml")
		}},
		{"OMNIGENT_CONFIG that is a link", false, func(t *testing.T, h *omnigentHarness) string {
			target := filepath.Join(h.home, "dotfiles", "omnigent.yaml")
			writeRemovedFixture(t, target, omnigentPatchedConfig, 0o600)
			link := filepath.Join(h.home, "policies", "active.yaml")
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			t.Setenv("OMNIGENT_CONFIG", link)
			// The test writes the config through the link.
			return link
		}},
		{"a config the hook contract lock names", false, func(t *testing.T, h *omnigentHarness) string {
			path := filepath.Join(h.home, "work", "omnigent.yaml")
			if err := SaveHookContractLockEntry(h.dataDir, HookContractLockEntry{
				Connector: removedOmnigentID,
				Locations: ConnectorLocations{HookConfigPaths: []string{path}},
			}); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		// Review fixes (loop round 1): a relative or ~ OMNIGENT_CONFIG_HOME,
		// and a relative config the lock names, were skipped, so the module
		// and the .pth line went while that config still named them.
		{"relative OMNIGENT_CONFIG_HOME", false, func(t *testing.T, h *omnigentHarness) string {
			t.Chdir(h.home)
			t.Setenv("OMNIGENT_CONFIG_HOME", "./policyhome")
			return filepath.Join(h.home, "policyhome", "config.yaml")
		}},
		{"relative OMNIGENT_CONFIG_HOME with a config home", true, func(t *testing.T, h *omnigentHarness) string {
			t.Chdir(h.home)
			t.Setenv("OMNIGENT_CONFIG_HOME", "policyhome")
			return filepath.Join(h.home, "policyhome", "config.yaml")
		}},
		{"OMNIGENT_CONFIG_HOME under ~", false, func(t *testing.T, h *omnigentHarness) string {
			t.Setenv("OMNIGENT_CONFIG_HOME", "~/policyhome")
			return filepath.Join(h.home, "policyhome", "config.yaml")
		}},
		{"a relative config the hook contract lock names", false, func(t *testing.T, h *omnigentHarness) string {
			t.Chdir(h.home)
			if err := SaveHookContractLockEntry(h.dataDir, HookContractLockEntry{
				Connector: removedOmnigentID,
				Locations: ConnectorLocations{HookConfigPaths: []string{filepath.Join("work", "omnigent.yaml")}},
			}); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(h.home, "work", "omnigent.yaml")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOmnigentHarness(t, tc.configHome)
			h.setUp(t, omnigentSetup{config: omnigentOperatorConfig})
			active := tc.active(t, h)
			writeRemovedFixture(t, active, omnigentPatchedConfig, 0o600)
			before := h.state(t, active)
			for run := 1; run <= 2; run++ {
				h.notices.Reset()
				if err := h.teardown(t); err != nil {
					t.Fatalf("Teardown run %d = %v, want the state left for manual cleanup", run, err)
				}
				requireRemovedSnapshot(t, "a teardown while a config OmniGent reads names the module", before)
				h.requirePeerUnchanged(t)
				if got := strings.Count(h.notices.String(), "WARNING"); got != 1 || !strings.Contains(h.notices.String(), active) {
					t.Fatalf("run %d printed %d warnings, want one naming %s:\n%s", run, got, active, h.notices)
				}
				if record, ok := h.manualRecord(t, removedOmnigentID); !ok || !record.lists(active) {
					t.Fatalf("manual cleanup record = %+v, %v; want %s", record, ok, active)
				}
				if err := h.verify(); err != nil {
					t.Fatalf("VerifyClean with the steps recorded: %v", err)
				}
			}
			if err := os.Remove(removedCleanupRecordPath(h.dataDir, removedOmnigentID)); err != nil {
				t.Fatal(err)
			}
			if err := h.verify(); err == nil || !strings.Contains(err.Error(), active) {
				t.Fatalf("VerifyClean without the record = %v, want %s named", err, active)
			}

			writeRemovedFixture(t, active, omnigentCleanedConfig, 0o600)
			h.notices.Reset()
			if err := h.teardown(t); err != nil {
				t.Fatalf("Teardown after the manual step: %v", err)
			}
			if h.notices.Len() != 0 {
				t.Fatalf("finished teardown printed: %s", h.notices)
			}
			h.requireDone(t)
			requireRemovedSnapshot(t, "teardown", map[string]string{h.configPath: omnigentOperatorConfig})
			if data, err := os.ReadFile(active); err != nil || string(data) != omnigentCleanedConfig {
				t.Fatalf("teardown changed %s: %q, %v", active, data, err)
			}
		})
	}

	t.Run("OMNIGENT_CONFIG that does not name the module", func(t *testing.T) {
		h := newOmnigentHarness(t, false)
		h.setUp(t, omnigentSetup{config: omnigentOperatorConfig})
		active := filepath.Join(h.home, "policies", "active.yaml")
		t.Setenv("OMNIGENT_CONFIG", active)
		writeRemovedFixture(t, active, omnigentCleanedConfig, 0o600)
		if err := h.teardown(t); err != nil {
			t.Fatalf("Teardown: %v", err)
		}
		if h.notices.Len() != 0 {
			t.Fatalf("a clean teardown printed: %s", h.notices)
		}
		h.requireDone(t)
		requireRemovedSnapshot(t, "teardown", map[string]string{active: omnigentCleanedConfig, h.configPath: omnigentOperatorConfig})
	})
}

// Review loop round 4: a failed cleanup's rollback wrote the bytes the plan
// read over every file it had changed without looking at them, so a change
// another process made to such a file in the meantime was lost. Now a file is
// written back only while it holds what the cleanup wrote: one changed since
// (edited, deleted, recreated or replaced by a link, the failing file itself
// included) is kept as it is and named in the error, the other files are
// rolled back, the backup records and the token stay, and the retry plans
// from what is there.
func TestRemovedCleanupRollbackKeepsAConcurrentChange(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the parent directory is synced only on Linux and macOS")
	}
	const userModule = "def check(event):\n    return None\n"
	edited := omnigentOperatorConfig + "# my edit\n"
	allWrites := omnigentSetup{config: omnigentOperatorConfig, pth: "/opt/user-site\n", module: userModule}
	for _, tc := range []struct {
		name  string
		setup omnigentSetup
		// failDir is the directory whose sync fails; during changes a file
		// first and returns it with the bytes it must keep.
		failDir func(h *omnigentHarness) string
		during  func(t *testing.T, h *omnigentHarness) (string, string)
		// retryLeaves: the retry leaves the changed file for the user.
		retryLeaves bool
	}{
		{name: "config.yaml edited after it was put back", setup: allWrites,
			failDir: func(h *omnigentHarness) string { return h.hookDir },
			during: func(t *testing.T, h *omnigentHarness) (string, string) {
				writeRemovedFixture(t, h.configPath, edited, 0o600)
				return h.configPath, edited
			}},
		{name: "config.yaml deleted after it was put back", setup: allWrites,
			failDir: func(h *omnigentHarness) string { return h.hookDir },
			during: func(t *testing.T, h *omnigentHarness) (string, string) {
				if err := os.Remove(h.configPath); err != nil {
					t.Fatal(err)
				}
				return h.configPath, removedMissing
			}},
		{name: "config.yaml replaced by a link after it was put back", setup: allWrites, retryLeaves: true,
			failDir: func(h *omnigentHarness) string { return h.hookDir },
			during: func(t *testing.T, h *omnigentHarness) (string, string) {
				target := filepath.Join(h.home, "elsewhere.yaml")
				writeRemovedFixture(t, target, edited, 0o600)
				if err := os.Remove(h.configPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, h.configPath); err != nil {
					t.Fatal(err)
				}
				return h.configPath, "symlink:" + target
			}},
		{name: ".pth edited after it was put back", setup: allWrites,
			failDir: func(h *omnigentHarness) string { return h.hookDir },
			during: func(t *testing.T, h *omnigentHarness) (string, string) {
				writeRemovedFixture(t, h.pthPath, "/opt/user-site\n/opt/more\n", 0o600)
				return h.pthPath, "/opt/user-site\n/opt/more\n"
			}},
		{name: ".pth recreated after the cleanup removed it", setup: omnigentSetup{config: omnigentOperatorConfig, module: userModule},
			failDir: func(h *omnigentHarness) string { return h.hookDir },
			during: func(t *testing.T, h *omnigentHarness) (string, string) {
				writeRemovedFixture(t, h.pthPath, "/opt/mine\n", 0o600)
				return h.pthPath, "/opt/mine\n"
			}},
		{name: "module edited while its own write failed", setup: allWrites,
			failDir: func(h *omnigentHarness) string { return h.hookDir },
			during: func(t *testing.T, h *omnigentHarness) (string, string) {
				writeRemovedFixture(t, h.modulePath, userModule+"# mine\n", 0o600)
				return h.modulePath, userModule + "# mine\n"
			}},
		{name: "config.yaml edited while its own write failed", setup: allWrites,
			failDir: func(h *omnigentHarness) string { return filepath.Dir(h.configPath) },
			during: func(t *testing.T, h *omnigentHarness) (string, string) {
				writeRemovedFixture(t, h.configPath, edited, 0o600)
				return h.configPath, edited
			}},
	} {
		t.Run("omnigent "+tc.name, func(t *testing.T) {
			h := newOmnigentHarness(t, false)
			h.setUp(t, tc.setup)
			want := h.state(t)
			var changed string
			failed := failParentSyncOnceWhile(t, tc.failDir(h), func() {
				var body string
				changed, body = tc.during(t, h)
				want[changed] = body
			})
			err := h.teardown(t)
			if err == nil || !strings.Contains(err.Error(), "injected") || !strings.Contains(err.Error(), changed) ||
				!strings.Contains(err.Error(), "kept as it is") {
				t.Fatalf("Teardown = %v, want the injected failure and %s kept", err, changed)
			}
			if *failed != 1 {
				t.Fatalf("the injected failure ran %d times", *failed)
			}
			requireRemovedSnapshot(t, "a failed teardown that met a concurrent change", want)
			h.requirePeerUnchanged(t)
			if _, ok := h.manualRecord(t, removedOmnigentID); ok {
				t.Fatal("a failed teardown recorded manual steps")
			}

			h.notices.Reset()
			if err := h.teardown(t); err != nil {
				t.Fatalf("retry: %v", err)
			}
			requireRemovedSnapshot(t, "retry", map[string]string{changed: want[changed]})
			record, left := h.manualRecord(t, removedOmnigentID)
			if tc.retryLeaves {
				if !left || !record.lists(changed) {
					t.Fatalf("manual cleanup record = %+v, %v; want %s", record, left, changed)
				}
				return
			}
			if left {
				t.Fatalf("retry left manual steps: %+v", record)
			}
			if err := h.verify(); err != nil {
				t.Fatalf("VerifyClean after the retry: %v", err)
			}
			for _, path := range h.records() {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("%s survived the retry: %v", path, err)
				}
			}
			if token, err := LoadHookAPIToken(h.dataDir, removedOmnigentID); err != nil || token != "" {
				t.Fatalf("omnigent token = %q, %v; want revoked", token, err)
			}
			h.requirePeerUnchanged(t)
		})
	}

	t.Run("openhands hooks.json edited after it was put back", func(t *testing.T) {
		h := newOpenHandsHarness(t, false)
		h.setUp(t, true)
		want := h.state(t)
		failParentSyncOnceWhile(t, filepath.Dir(h.script), func() {
			writeRemovedFixture(t, h.hooksPath, `{}`, 0o600)
			want[h.hooksPath] = `{}`
		})
		if err := h.teardown(); err == nil || !strings.Contains(err.Error(), h.hooksPath) || !strings.Contains(err.Error(), "kept as it is") {
			t.Fatalf("Teardown = %v, want %s kept", err, h.hooksPath)
		}
		requireRemovedSnapshot(t, "a failed teardown that met a concurrent change", want)
		h.requirePeerUnchanged(t)
		if err := h.teardown(); err != nil {
			t.Fatalf("retry: %v", err)
		}
		h.requireDone(t)
		requireRemovedSnapshot(t, "retry", map[string]string{h.hooksPath: `{}`})
	})
}

// A hooks file or config teardown only reads (no backup record names it) is
// read through a link: a link to a hooks file that names the script keeps
// everything for the user, and a link to one that does not lets the cleanup
// finish (review loop round 4).
func TestRemovedOpenHandsTeardownReadsAnUnrecordedHooksFileThroughALink(t *testing.T) {
	h := newOpenHandsHarness(t, false)
	h.setUp(t, true)
	target := filepath.Join(h.home, "dotfiles", "hooks.json")
	writeRemovedFixture(t, target, openHandsHooksRunning(t, h.script), 0o600)
	workspace := filepath.Join(h.home, "repo", ".openhands", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(workspace), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, workspace); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(h.script)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveHookContractLockEntry(h.dataDir, HookContractLockEntry{
		Connector:         removedOpenHandsID,
		HookScriptDigests: map[string]string{removedOpenHandsHookScript: "sha256:" + sha256Hex(data)},
		Locations:         ConnectorLocations{HookConfigPaths: []string{h.hooksPath, workspace}},
	}); err != nil {
		t.Fatal(err)
	}
	before := h.state(t)
	for path, body := range removedSnapshot(t, workspace, target) {
		before[path] = body
	}
	if err := h.teardown(); err != nil {
		t.Fatalf("Teardown = %v, want the state left for manual cleanup", err)
	}
	requireRemovedSnapshot(t, "a teardown with a linked hooks file that names the script", before)
	if record, ok := h.manualRecord(t, removedOpenHandsID); !ok || !record.lists(workspace) {
		t.Fatalf("manual cleanup record = %+v, %v; want %s", record, ok, workspace)
	}
	writeRemovedFixture(t, target, `{}`, 0o600)
	h.notices.Reset()
	if err := h.teardown(); err != nil {
		t.Fatalf("Teardown after the manual step: %v", err)
	}
	if h.notices.Len() != 0 {
		t.Fatalf("finished teardown printed: %s", h.notices)
	}
	h.requireDone(t)
	requireRemovedSnapshot(t, "teardown", map[string]string{workspace: "symlink:" + target, target: `{}`})
}

// Review fixes (loop round 1): teardown skipped a config home or lock path
// that was not absolute. It resolves each the ways an older release may have
// read it: from the working directory, and ~ also as the user's home.
func TestRemovedResolvedPaths(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	home := homePath()
	absolute := filepath.Join(cwd, "abs", "config.yaml")
	for _, tc := range []struct {
		value string
		want  []string
	}{
		{"", nil},
		{"  ", nil},
		{absolute, []string{absolute}},
		{" " + absolute + " ", []string{absolute}},
		{filepath.Join("policyhome", "..", "policyhome"), []string{filepath.Join(cwd, "policyhome")}},
		{"./policyhome", []string{filepath.Join(cwd, "policyhome")}},
		{"~", []string{home, filepath.Join(cwd, "~")}},
		{"~/policyhome", []string{filepath.Join(home, "policyhome"), filepath.Join(cwd, "~", "policyhome")}},
	} {
		got := removedResolvedPaths(tc.value)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("removedResolvedPaths(%q) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

// --- Review fixes (G-deadcode loop round 2) ---

// removedRecordVariants are files at the OmniGent record path that
// DefenseClaw cannot prove it wrote: a user's file, another connector's
// record, its own record with one byte more, and one with a field it never
// writes.
func removedRecordVariants(t *testing.T) map[string]string {
	t.Helper()
	items := []removedCleanupItem{{Path: "/x", Reason: "r", Step: "s"}}
	own, err := removedConnectorBase{name: removedOmnigentID, label: "OmniGent"}.recordBytes(items)
	if err != nil {
		t.Fatal(err)
	}
	other, err := removedConnectorBase{name: removedOpenHandsID, label: "OpenHands"}.recordBytes(items)
	if err != nil {
		t.Fatal(err)
	}
	extra := strings.Replace(string(own), `"version": 1,`, `"version": 1, "owner": "me",`, 1)
	return map[string]string{
		"a user file":              "theirs",
		"another connector record": string(other),
		"one byte more":            string(own) + "\n",
		"an unknown field":         extra,
	}
}

// A file at the record path that DefenseClaw cannot prove it wrote is never
// overwritten (cleanup left for the user) nor removed (finished cleanup), and
// lists no steps for VerifyClean.
func TestRemovedManualCleanupRecordNeverReplacesOrRemovesAForeignFile(t *testing.T) {
	for name, body := range removedRecordVariants(t) {
		t.Run(name, func(t *testing.T) {
			for _, finished := range []bool{false, true} {
				t.Run(map[bool]string{false: "left", true: "finished"}[finished], func(t *testing.T) {
					h := newOmnigentHarness(t, false)
					h.setUp(t, omnigentSetup{config: omnigentOperatorConfig})
					if !finished {
						writeRemovedFixture(t, h.configPath, omnigentPatchedConfig+"model: local\n", 0o600)
					}
					record := removedCleanupRecordPath(h.dataDir, removedOmnigentID)
					writeRemovedFixture(t, record, body, 0o600)
					err := h.teardown(t)
					if err == nil || !strings.Contains(err.Error(), record) {
						t.Fatalf("finished=%t: Teardown = %v, want the file at the record path left and named", finished, err)
					}
					requireRemovedSnapshot(t, "a foreign record", map[string]string{record: body})
					if !finished {
						if err := h.verify(); err == nil {
							t.Fatal("VerifyClean trusted steps from a file DefenseClaw did not write")
						}
					}
				})
			}
		})
	}
}

// The record folder is never a link: no record is written, replaced, removed
// or read through one, wherever it leads.
func TestRemovedManualCleanupRecordFolderIsNeverALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	ownBytes := func(t *testing.T, h *omnigentHarness) string {
		t.Helper()
		// Exactly the record teardown would write for this state.
		conn := removedOmnigentConnector{removedConnectorBase{name: removedOmnigentID, label: "OmniGent"}}
		p, err := conn.plan(h.opts)
		if err != nil {
			t.Fatal(err)
		}
		data, err := conn.recordBytes(p.manual)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	for _, tc := range []struct {
		name     string
		finished bool
		existing func(*testing.T, *omnigentHarness) string // "" = no file where the link leads
	}{
		{name: "left, nothing there", existing: func(*testing.T, *omnigentHarness) string { return "" }},
		{name: "left, a user file", existing: func(*testing.T, *omnigentHarness) string { return "theirs" }},
		{name: "left, a record", existing: ownBytes},
		{name: "finished, a user file", finished: true, existing: func(*testing.T, *omnigentHarness) string { return "theirs" }},
		{name: "finished, a record", finished: true, existing: ownBytes},
	} {
		for _, inHome := range []bool{true, false} {
			t.Run(tc.name+map[bool]string{true: ", in the home", false: ", outside the home"}[inHome], func(t *testing.T) {
				h := newOmnigentHarness(t, false)
				h.setUp(t, omnigentSetup{config: omnigentOperatorConfig})
				if !tc.finished {
					writeRemovedFixture(t, h.configPath, omnigentPatchedConfig+"model: local\n", 0o600)
				}
				elsewhere := t.TempDir()
				if inHome {
					elsewhere = filepath.Join(h.home, "elsewhere")
					if err := os.Mkdir(elsewhere, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				target := filepath.Join(elsewhere, removedOmnigentID+".json")
				want := map[string]string{target: removedMissing}
				if body := tc.existing(t, h); body != "" {
					writeRemovedFixture(t, target, body, 0o600)
					want[target] = body
				}
				folder := filepath.Join(h.dataDir, removedCleanupDir)
				if err := os.Symlink(elsewhere, folder); err != nil {
					t.Fatal(err)
				}
				if !tc.finished {
					// A record where the link leads lists no steps.
					if err := h.verify(); err == nil {
						t.Fatal("VerifyClean read the record through a linked folder")
					}
				}
				if err := h.teardown(t); err == nil || !strings.Contains(err.Error(), "not a plain directory") {
					t.Fatalf("Teardown = %v, want the linked record folder refused", err)
				}
				requireRemovedSnapshot(t, "a linked record folder", want)
				requireRemovedSnapshot(t, "a linked record folder", map[string]string{folder: "symlink:" + elsewhere})
			})
		}
	}
}

// A record DefenseClaw wrote is replaced when the steps change and removed
// when the cleanup finishes.
func TestRemovedManualCleanupRecordReplacesAndRemovesItsOwn(t *testing.T) {
	h := newOmnigentHarness(t, false)
	h.setUp(t, omnigentSetup{config: omnigentOperatorConfig})
	writeRemovedFixture(t, h.configPath, omnigentPatchedConfig+"model: local\n", 0o600)
	stale, err := removedConnectorBase{name: removedOmnigentID, label: "OmniGent"}.recordBytes(
		[]removedCleanupItem{{Path: filepath.Join(h.home, "stale"), Reason: "r", Step: "s"}})
	if err != nil {
		t.Fatal(err)
	}
	record := removedCleanupRecordPath(h.dataDir, removedOmnigentID)
	writeRemovedFixture(t, record, string(stale), 0o600)
	if err := h.teardown(t); err != nil {
		t.Fatalf("Teardown over its own record: %v", err)
	}
	got, ok := h.manualRecord(t, removedOmnigentID)
	if !ok || !got.lists(h.configPath) || got.lists(filepath.Join(h.home, "stale")) {
		t.Fatalf("record = %+v, %t; want the current steps only", got, ok)
	}
	if err := h.verify(); err != nil {
		t.Fatalf("VerifyClean with its own record: %v", err)
	}
	writeRemovedFixture(t, h.configPath, omnigentCleanedConfig, 0o600)
	if err := h.teardown(t); err != nil {
		t.Fatalf("Teardown after the manual step: %v", err)
	}
	h.requireDone(t)
}

// --- Review fixes (G-deadcode loop round 3) ---

// removedOpenHandsRuntimeRecord is the runtime record an older release's hook
// writer kept for OpenHands (0.8.10 through 1.0.3).
func removedOpenHandsRuntimeRecord(mode string) string {
	return "DEFENSECLAW_CONNECTOR=openhands\nDEFENSECLAW_FAIL_MODE=" + mode + "\n"
}

// The OpenHands runtime record (.hookcfg.openhands) is removed only while it
// holds exactly what an older release wrote. Any other file there is left
// byte for byte, with everything else, for the user.
func TestRemovedOpenHandsTeardownNeverRemovesAForeignRuntimeRecord(t *testing.T) {
	for _, mode := range []string{"closed", "open"} {
		t.Run("its own, fail mode "+mode, func(t *testing.T) {
			h := newOpenHandsHarness(t, false)
			h.setUp(t, true)
			writeRemovedFixture(t, filepath.Join(h.dataDir, "hooks", ".hookcfg.openhands"), removedOpenHandsRuntimeRecord(mode), 0o600)
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			h.requireDone(t)
		})
	}
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, h *openHandsHarness, path string) // replaces the record
		links bool
	}{
		{name: "a user file", plant: func(t *testing.T, _ *openHandsHarness, path string) {
			writeRemovedFixture(t, path, "theirs\n", 0o600)
		}},
		{name: "the Codex record", plant: func(t *testing.T, _ *openHandsHarness, path string) {
			writeRemovedFixture(t, path, "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=closed\n", 0o600)
		}},
		{name: "its own record with one byte more", plant: func(t *testing.T, _ *openHandsHarness, path string) {
			writeRemovedFixture(t, path, removedOpenHandsRuntimeRecord("closed")+"\n", 0o600)
		}},
		{name: "its own record with CRLF", plant: func(t *testing.T, _ *openHandsHarness, path string) {
			writeRemovedFixture(t, path, "DEFENSECLAW_CONNECTOR=openhands\r\nDEFENSECLAW_FAIL_MODE=closed\r\n", 0o600)
		}},
		{name: "an unknown fail mode", plant: func(t *testing.T, _ *openHandsHarness, path string) {
			writeRemovedFixture(t, path, removedOpenHandsRuntimeRecord("audit"), 0o600)
		}},
		{name: "a link to a user file", links: true, plant: func(t *testing.T, h *openHandsHarness, path string) {
			target := filepath.Join(h.home, "notes.txt")
			writeRemovedFixture(t, target, removedOpenHandsRuntimeRecord("closed"), 0o600)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a directory", plant: func(t *testing.T, _ *openHandsHarness, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			writeRemovedFixture(t, filepath.Join(path, "keep"), "theirs\n", 0o600)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.links && runtime.GOOS == "windows" {
				t.Skip("symlinks need privileges on Windows")
			}
			h := newOpenHandsHarness(t, false)
			h.setUp(t, true)
			path := filepath.Join(h.dataDir, "hooks", ".hookcfg.openhands")
			tc.plant(t, h, path)
			paths := []string{h.hooksPath, h.script, filepath.Join(h.home, "notes.txt"),
				filepath.Join(h.dataDir, "hooks", ".otlp-openhands.token"),
				removedTokenFile(t, h.dataDir, removedOpenHandsID),
				managedFileBackupPath(h.dataDir, removedOpenHandsID, "config")}
			if info, err := os.Lstat(path); err == nil && info.IsDir() {
				paths = append(paths, filepath.Join(path, "keep"))
			} else {
				paths = append(paths, path)
			}
			before := removedSnapshot(t, paths...)
			for run := 1; run <= 2; run++ {
				h.notices.Reset()
				if err := h.teardown(); err != nil {
					t.Fatalf("Teardown run %d = %v, want the state left for manual cleanup", run, err)
				}
				requireRemovedSnapshot(t, "a teardown with a runtime record DefenseClaw did not write", before)
				h.requirePeerUnchanged(t)
				if !strings.Contains(h.notices.String(), path) {
					t.Fatalf("run %d did not name %s:\n%s", run, path, h.notices)
				}
				if record, ok := h.manualRecord(t, removedOpenHandsID); !ok || !record.lists(path) {
					t.Fatalf("manual cleanup record = %+v, %v; want %s", record, ok, path)
				}
			}
			if err := h.verify(); err != nil {
				t.Fatalf("VerifyClean with the manual step recorded: %v", err)
			}
			// The user moves the file away; the next teardown finishes.
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown after the manual step: %v", err)
			}
			h.requireDone(t)
		})
	}
}

// removedFinishCase makes one step after the file changes impossible, and
// undoes that.
type removedFinishCase struct {
	name string
	// block breaks the step; it returns what the error must name and the
	// paths it planted, with their contents.
	block func(t *testing.T, dataDir, connectorName, home string) (string, map[string]string)
	// unblock lets the step through again.
	unblock func(t *testing.T, dataDir, connectorName string)
	// afterChanges: the step fails only after the changes (so they are
	// rolled back); otherwise it is checked before any change.
	afterChanges bool
}

func removedFinishCases() []removedFinishCase {
	folder := func(dataDir string) string { return filepath.Join(dataDir, removedCleanupDir) }
	unlinkFolder := func(t *testing.T, dataDir, _ string) {
		t.Helper()
		if err := os.RemoveAll(folder(dataDir)); err != nil {
			t.Fatal(err)
		}
	}
	otlp := func(dataDir, connectorName string) string {
		return filepath.Join(dataDir, "hooks", otlpPathTokenFileName(OTLPPathTokenScope(connectorName)))
	}
	return []removedFinishCase{
		{name: "the record folder is a link", block: func(t *testing.T, dataDir, _ string, home string) (string, map[string]string) {
			elsewhere := filepath.Join(home, "elsewhere")
			writeRemovedFixture(t, filepath.Join(elsewhere, "keep"), "theirs\n", 0o600)
			if err := os.Symlink(elsewhere, folder(dataDir)); err != nil {
				t.Fatal(err)
			}
			return "not a plain directory", map[string]string{
				folder(dataDir): "symlink:" + elsewhere, filepath.Join(elsewhere, "keep"): "theirs\n"}
		}, unblock: unlinkFolder},
		{name: "the record folder is a file", block: func(t *testing.T, dataDir, _ string, _ string) (string, map[string]string) {
			writeRemovedFixture(t, folder(dataDir), "theirs\n", 0o600)
			return "not a plain directory", map[string]string{folder(dataDir): "theirs\n"}
		}, unblock: unlinkFolder},
		{name: "a user file at the record path", block: func(t *testing.T, dataDir, connectorName string, _ string) (string, map[string]string) {
			path := removedCleanupRecordPath(dataDir, connectorName)
			writeRemovedFixture(t, path, "theirs\n", 0o600)
			return path, map[string]string{path: "theirs\n"}
		}, unblock: unlinkFolder},
		{name: "a token is a link", afterChanges: true, block: func(t *testing.T, dataDir, connectorName string, home string) (string, map[string]string) {
			target := filepath.Join(home, "token-target")
			writeRemovedFixture(t, target, "theirs\n", 0o600)
			path := otlp(dataDir, connectorName)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			return path, map[string]string{path: "symlink:" + target, target: "theirs\n"}
		}, unblock: func(t *testing.T, dataDir, connectorName string) {
			t.Helper()
			if err := os.Remove(otlp(dataDir, connectorName)); err != nil {
				t.Fatal(err)
			}
		}},
	}
}

// A cleanup that cannot finish changes nothing: a step after the file
// changes (clearing the manual-cleanup record, revoking a token) is checked
// before them, or, when it still fails, rolls them back and keeps the backup
// records, so the next start retries from the same state.
func TestRemovedTeardownThatCannotFinishChangesNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	for _, tc := range removedFinishCases() {
		t.Run("OmniGent, "+tc.name, func(t *testing.T) {
			h := newOmnigentHarness(t, false)
			h.setUp(t, omnigentSetup{config: omnigentOperatorConfig})
			names, planted := tc.block(t, h.dataDir, removedOmnigentID, h.home)
			before := h.state(t)
			if tc.afterChanges {
				// The hook token goes before the failing step: nothing
				// accepts it any more, so it is not put back.
				delete(before, removedTokenFile(t, h.dataDir, removedOmnigentID))
			}
			for path, body := range planted {
				before[path] = body
			}
			err := h.teardown(t)
			if err == nil || !strings.Contains(err.Error(), names) {
				t.Fatalf("Teardown = %v, want an error naming %s", err, names)
			}
			requireRemovedSnapshot(t, "a teardown that cannot finish", before)
			h.requirePeerUnchanged(t)
			if err := h.verify(); err == nil {
				t.Fatal("VerifyClean passed while every file is still as DefenseClaw wrote it")
			}
			tc.unblock(t, h.dataDir, removedOmnigentID)
			if err := h.teardown(t); err != nil {
				t.Fatalf("Teardown once the step can finish: %v", err)
			}
			h.requireDone(t)
		})
		t.Run("OpenHands, "+tc.name, func(t *testing.T) {
			h := newOpenHandsHarness(t, false)
			h.setUp(t, true)
			names, planted := tc.block(t, h.dataDir, removedOpenHandsID, h.home)
			before := h.state(t)
			if tc.afterChanges {
				delete(before, removedTokenFile(t, h.dataDir, removedOpenHandsID))
			}
			for path, body := range planted {
				before[path] = body
			}
			err := h.teardown()
			if err == nil || !strings.Contains(err.Error(), names) {
				t.Fatalf("Teardown = %v, want an error naming %s", err, names)
			}
			requireRemovedSnapshot(t, "a teardown that cannot finish", before)
			h.requirePeerUnchanged(t)
			if err := h.verify(); err == nil {
				t.Fatal("VerifyClean passed while every file is still as DefenseClaw wrote it")
			}
			tc.unblock(t, h.dataDir, removedOpenHandsID)
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown once the step can finish: %v", err)
			}
			h.requireDone(t)
		})
	}
}

// A removed connector's teardown never writes the hook contract lock or the
// shared .hookcfg, which hold the surviving connectors' entries: on a managed
// host only the managed writer may write them. Each caller that drops the
// connector clears its entry afterwards in its own mode, and the surviving
// entries stay as they were.
func TestRemovedTeardownLeavesTheHookContractLockToItsCaller(t *testing.T) {
	sharedRuntime := func(t *testing.T, dataDir, connectorName string) string {
		t.Helper()
		body, err := json.MarshalIndent(hookConfigSidecar{
			Version: 2, GatewayAddr: "127.0.0.1:18970",
			FailModes: map[string]string{"codex": "closed", connectorName: "closed"},
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dataDir, "hooks", hookConfigSidecarName)
		writeRemovedFixture(t, path, string(body)+"\n", 0o600)
		return path
	}
	codexEntry := HookContractLockEntry{Connector: "codex", HookScriptDigests: map[string]string{"codex-hook.sh": "sha256:" + strings.Repeat("c", 64)}}
	check := func(t *testing.T, dataDir, connectorName string, teardown func() error, done func(*testing.T)) {
		t.Helper()
		if err := SaveHookContractLockEntry(dataDir, codexEntry); err != nil {
			t.Fatal(err)
		}
		if LoadHookContractLockEntry(dataDir, connectorName).Connector == "" {
			if err := SaveHookContractLockEntry(dataDir, HookContractLockEntry{Connector: connectorName}); err != nil {
				t.Fatal(err)
			}
		}
		lock := filepath.Join(dataDir, hookContractLockFile)
		shared := sharedRuntime(t, dataDir, connectorName)
		before := removedSnapshot(t, lock, shared)
		for run := 1; run <= 2; run++ {
			if err := teardown(); err != nil {
				t.Fatalf("Teardown run %d: %v", run, err)
			}
			requireRemovedSnapshot(t, "a removed connector's teardown", before)
		}
		done(t)
		// The caller's clear, in its mode, drops only this entry.
		if err := ClearHookContractLockEntry(dataDir, connectorName); err != nil {
			t.Fatalf("the caller's lock clear: %v", err)
		}
		if got := LoadHookContractLockEntry(dataDir, connectorName); got.Connector != "" {
			t.Fatalf("%s lock entry survived the caller's clear: %+v", connectorName, got)
		}
		if got := LoadHookContractLockEntry(dataDir, "codex"); got.Connector != "codex" ||
			got.HookScriptDigests["codex-hook.sh"] != codexEntry.HookScriptDigests["codex-hook.sh"] {
			t.Fatalf("surviving Codex lock entry = %+v", got)
		}
		data, err := os.ReadFile(shared)
		if err != nil {
			t.Fatal(err)
		}
		var state hookConfigSidecar
		if err := json.Unmarshal(data, &state); err != nil || state.FailModes["codex"] != "closed" || state.FailModes[connectorName] != "" {
			t.Fatalf("shared runtime state after the caller's clear = %+v, %v", state, err)
		}
	}
	for _, managedMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "OmniGent, per-user", true: "OmniGent, managed"}[managedMode], func(t *testing.T) {
			h := newOmnigentHarness(t, false)
			h.opts.ManagedEnterprise = managedMode
			h.setUp(t, omnigentSetup{config: omnigentOperatorConfig})
			check(t, h.dataDir, removedOmnigentID, func() error { return h.teardown(t) }, h.requireDone)
		})
	}
	t.Run("OpenHands", func(t *testing.T) {
		h := newOpenHandsHarness(t, false)
		h.setUp(t, true)
		check(t, h.dataDir, removedOpenHandsID, h.teardown, h.requireDone)
	})
}
