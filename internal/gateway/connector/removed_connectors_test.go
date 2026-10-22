// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: the teardown-only OpenHands and OmniGent connectors (removed.go).
// Delete with that file.

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
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
	// The home is not named after the test, as t.TempDir is: a comma or a
	// # in a test's name made every path under it one the OpenHands check
	// cannot rule out, so a case passed for its name alone.
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
	// The startup file a shell reads when these are set is checked too.
	t.Setenv("BASH_ENV", "")
	t.Setenv("ENV", "")
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

			if _, err := os.Lstat(managedFileBackupPath(h.dataDir, removedOpenHandsID, "config")); os.IsNotExist(err) {
				// With no record of the hooks file setup found, a hook
				// DefenseClaw cannot see through (here a command found on
				// PATH) keeps the script, not the tombstone (review loop
				// round 3); one it can rule out lets the cleanup finish
				// (round 4).
				writeRemovedFixture(t, h.hooksPath, openHandsHooksRunning(t, "audit-hook"), 0o600)
				h.notices.Reset()
				if err := h.teardown(); err != nil {
					t.Fatalf("Teardown after the hooks step: %v", err)
				}
				if record, ok := h.manualRecord(t, removedOpenHandsID); !ok || !record.lists(h.script) || !record.lists(h.hooksPath) {
					t.Fatalf("manual cleanup record = %+v, %v; want the script and hooks.json", record, ok)
				}
			}
			writeRemovedFixture(t, h.hooksPath, openHandsOperatorHooks, 0o600)
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown after the manual step: %v", err)
			}
			h.requireDone(t)
		})
	}
}

// Review loop round 3: a recorded hooks.json the user changed so that it
// runs DefenseClaw's hook script without naming its path (a link, a
// wrapper, $HOME, a relative or doubled path) was taken as clean, and the
// still-run script became the tombstone, which exits 0: an allow-all hook
// with no warning. Now such a hooks file and the script are left for the
// user, byte for byte, until the script is gone.
func TestRemovedOpenHandsTeardownKeepsAScriptAHookMayStillRun(t *testing.T) {
	hooks := func(command string) string {
		data, err := json.Marshal(map[string]interface{}{"pre_tool_use": []interface{}{map[string]interface{}{
			"matcher": "*", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": command}},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	for _, tc := range []struct {
		name       string
		configHome bool
		noRecord   bool
		// command returns the hook command and any file it made.
		command func(t *testing.T, h *openHandsHarness) (string, []string)
	}{
		{name: "through a symlink", command: func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := filepath.Join(h.home, "bin", "oh-hook")
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(h.script, link); err != nil {
				t.Fatal(err)
			}
			return link, []string{link}
		}},
		{name: "through a wrapper", command: func(t *testing.T, h *openHandsHarness) (string, []string) {
			wrapper := filepath.Join(h.home, "bin", "wrap.sh")
			writeRemovedFixture(t, wrapper, "#!/bin/sh\nexec \"$HOME/.defenseclaw/hooks/openhands-hook.sh\" \"$@\"\n", 0o700)
			return wrapper + " --audit", []string{wrapper}
		}},
		{name: "through $HOME", command: func(t *testing.T, h *openHandsHarness) (string, []string) {
			return "$HOME/.defenseclaw/hooks/" + removedOpenHandsHookScript, nil
		}},
		{name: "by a relative path", command: func(t *testing.T, h *openHandsHarness) (string, []string) {
			return "cd ~/.defenseclaw/hooks && ./" + removedOpenHandsHookScript, nil
		}},
		{name: "by a doubled path", command: func(t *testing.T, h *openHandsHarness) (string, []string) {
			return filepath.Join(h.dataDir, "hooks") + "//" + removedOpenHandsHookScript, nil
		}},
		{name: "config home, through a symlink", configHome: true, command: func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := filepath.Join(h.home, "oh-hook")
			if err := os.Symlink(h.script, link); err != nil {
				t.Fatal(err)
			}
			return link, []string{link}
		}},
		{name: "no record, through a symlink", noRecord: true, command: func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := filepath.Join(h.home, "oh-hook")
			if err := os.Symlink(h.script, link); err != nil {
				t.Fatal(err)
			}
			return link, []string{link}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOpenHandsHarness(t, tc.configHome)
			h.setUp(t, true)
			if tc.noRecord {
				discardManagedFileBackup(h.dataDir, removedOpenHandsID, "config")
			}
			command, made := tc.command(t, h)
			writeRemovedFixture(t, h.hooksPath, hooks(command), 0o600)
			before := h.state(t)
			for path, body := range removedSnapshot(t, made...) {
				before[path] = body
			}
			for run := 1; run <= 2; run++ {
				h.notices.Reset()
				if err := h.teardown(); err != nil {
					t.Fatalf("Teardown run %d = %v, want the state left for manual cleanup", run, err)
				}
				requireRemovedSnapshot(t, "a teardown that cannot prove no hook runs the script", before)
				h.requirePeerUnchanged(t)
				notice := h.notices.String()
				if got := strings.Count(notice, "WARNING"); got != 1 || !strings.Contains(notice, h.hooksPath) || !strings.Contains(notice, h.script) {
					t.Fatalf("run %d printed %d warnings, want one naming %s and %s:\n%s", run, got, h.hooksPath, h.script, notice)
				}
				if record, ok := h.manualRecord(t, removedOpenHandsID); !ok || !record.lists(h.hooksPath) || !record.lists(h.script) {
					t.Fatalf("manual cleanup record = %+v, %v; want hooks.json and the script", record, ok)
				}
				if err := h.verify(); err != nil {
					t.Fatalf("VerifyClean with the steps recorded: %v", err)
				}
			}
			if err := os.Remove(removedCleanupRecordPath(h.dataDir, removedOpenHandsID)); err != nil {
				t.Fatal(err)
			}
			if err := h.verify(); err == nil || !strings.Contains(err.Error(), "openhands cleanup incomplete") {
				t.Fatalf("VerifyClean without the record = %v, want the cleanup named incomplete", err)
			}

			// The user removes the script: nothing can run it any more.
			if err := os.Remove(h.script); err != nil {
				t.Fatal(err)
			}
			h.notices.Reset()
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown after the manual step: %v", err)
			}
			if h.notices.Len() != 0 {
				t.Fatalf("finished teardown printed: %s", h.notices)
			}
			h.noScript = true
			h.requireDone(t)
			requireRemovedSnapshot(t, "teardown", map[string]string{h.hooksPath: hooks(command)})
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

// Review loop round 4: the copy of hooks.json setup found, which the cleanup
// puts back, was not checked: a hook in it that ran DefenseClaw's script
// without naming its path (a link, a wrapper, $HOME) was put back and the
// script became the tombstone, which exits 0. A hooks file already back to
// that copy was taken as proof too. Now every command in the hooks the
// cleanup leaves, the copy it puts back included, must be ruled out first;
// otherwise nothing changes, hooks.json and the script are left for the
// user, and the cleanup finishes once the script is gone.
func TestRemovedOpenHandsTeardownChecksTheHooksItPutsBack(t *testing.T) {
	wrapper := func(t *testing.T, h *openHandsHarness, body string) string {
		t.Helper()
		path := filepath.Join(h.home, "tools", "audit.sh")
		writeRemovedFixture(t, path, "#!/bin/sh\n"+body, 0o700)
		return path
	}
	// startup makes a startup file (name, under home) that runs a link to
	// the script, and a wrapper (text) the hook runs; it returns the files
	// it made, the wrapper first.
	startup := func(t *testing.T, h *openHandsHarness, name, text string) []string {
		t.Helper()
		link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "relay"))
		file := filepath.Join(h.home, name)
		writeRemovedFixture(t, file, link+"\n", 0o600)
		path := filepath.Join(h.home, "tools", "audit")
		writeRemovedFixture(t, path, text, 0o700)
		return []string{path, file, link}
	}
	// startupRun is startup with a plain wrapper the command runs.
	startupRun := func(name, command string) func(t *testing.T, h *openHandsHarness) (string, []string) {
		return func(t *testing.T, h *openHandsHarness) (string, []string) {
			made := startup(t, h, name, "#!/bin/sh\nexit 0\n")
			return command + " " + made[0], made
		}
	}
	// startupWrapper is startup with a wrapper (text) the hook runs.
	startupWrapper := func(name, text string) func(t *testing.T, h *openHandsHarness) (string, []string) {
		return func(t *testing.T, h *openHandsHarness) (string, []string) {
			made := startup(t, h, name, text)
			return made[0], made
		}
	}
	for _, tc := range []struct {
		name string
		// command returns the saved hook command and the files it made.
		command func(t *testing.T, h *openHandsHarness) (string, []string)
	}{
		{"a symlink", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "hooks-of-mine", "audit"))
			return link, []string{link}
		}},
		{"a hard link", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := filepath.Join(h.home, "hooks-of-mine", "audit")
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(h.script, link); err != nil {
				t.Fatal(err)
			}
			return link, []string{link}
		}},
		{"an interpreter that runs a symlink", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "hooks-of-mine", "audit"))
			return "/bin/sh " + link + " --audit 30", []string{link}
		}},
		{"an option that names a symlink", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "hooks-of-mine", "audit"))
			return "/bin/sh --rcfile=" + link, []string{link}
		}},
		{"an option that holds code", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "hooks-of-mine", "audit"))
			return "/bin/sh '-cexec " + link + "'", []string{link}
		}},
		{"an option with a relative value", func(t *testing.T, h *openHandsHarness) (string, []string) {
			return "/bin/sh --rcfile=bin/oh-audit", nil
		}},
		{"a quoted symlink", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "my hooks", "audit"))
			return "'" + link + "'", []string{link}
		}},
		{"a wrapper that names the script under HOME", func(t *testing.T, h *openHandsHarness) (string, []string) {
			path := wrapper(t, h, "exec \"$HOME/.defenseclaw/hooks/openhands-hook.sh\" \"$@\"\n")
			return path, []string{path}
		}},
		{"a wrapper that runs another symlink", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run"))
			path := wrapper(t, h, "exec "+link+" \"$@\"\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a symlink under ~", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run"))
			path := wrapper(t, h, "exec ~/lib/run \"$@\"\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a symlink under a quoted HOME", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run"))
			path := wrapper(t, h, "exec \"$HOME\"/lib/run \"$@\"\n")
			return path, []string{path, link}
		}},
		{"a wrapper's wrapper", func(t *testing.T, h *openHandsHarness) (string, []string) {
			inner := filepath.Join(h.home, "lib", "inner.sh")
			writeRemovedFixture(t, inner, "#!/bin/sh\nexec \"$HOME/.defenseclaw/hooks/openhands-hook.sh\"\n", 0o700)
			path := wrapper(t, h, "exec "+inner+"\n")
			return path, []string{path, inner}
		}},
		{"a wrapper that runs a symlink found on PATH", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "oh-audit"))
			path := wrapper(t, h, "exec oh-audit \"$@\"\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a relative path", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run"))
			path := wrapper(t, h, "cd "+filepath.Dir(link)+" && ./run\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a path from a variable", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run"))
			path := wrapper(t, h, "LIB="+filepath.Dir(link)+"\nexec \"$LIB/run\"\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a path beside itself", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "tools", "run"))
			path := wrapper(t, h, "exec \"$(dirname \"$0\")/run\"\n")
			return path, []string{path, link}
		}},
		// Review fixes (loop round 1): a wrapper path the check read only in
		// part (a blank in quotes, an escape, a joined quote, a character
		// outside the plain set, a relative path, a PATH list) was ruled out
		// through the parts it read, which are not there.
		{"a wrapper that runs a double-quoted path with a blank", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "audit dir", "relay-zq93"))
			path := wrapper(t, h, "exec \""+link+"\" \"$@\"\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a single-quoted path with a blank", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "audit dir", "relay"))
			path := wrapper(t, h, "exec '"+link+"'\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a quoted path with a blank under HOME", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "audit dir", "relay"))
			path := wrapper(t, h, "exec \"$HOME/audit dir/relay\" \"$@\"\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a path with an escaped blank", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "audit dir", "relay"))
			path := wrapper(t, h, "exec "+strings.ReplaceAll(link, " ", `\ `)+" \"$@\"\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a path joined from quoted parts", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "audit dir", "relay"))
			path := wrapper(t, h, "exec '"+filepath.Dir(link)+"'/relay\n")
			return path, []string{path, link}
		}},
		{"a Python wrapper that runs a quoted path with a blank", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "audit dir", "relay"))
			path := wrapper(t, h, "import os, sys\nos.execv(\""+link+"\", [\""+link+"\"] + sys.argv[1:])\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a path with a character outside the plain set", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "hooks#1", "relay"))
			path := wrapper(t, h, "exec "+link+" \"$@\"\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a path with letters outside ASCII", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "h\u00e4kchen", "relay"))
			path := wrapper(t, h, "exec "+link+"\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a relative path without ./", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run"))
			path := wrapper(t, h, "exec lib/run \"$@\"\n")
			return path, []string{path, link}
		}},
		{"a Python wrapper that builds the path at run time", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "audit dir", "relay"))
			path := filepath.Join(h.home, "tools", "audit")
			writeRemovedFixture(t, path, "#!/usr/bin/env python3\nimport os, sys\nos.execv(os.path.join(os.environ[\"HOME\"], \"audit dir\", \"relay\"), sys.argv)\n", 0o700)
			return path, []string{path, link}
		}},
		{"a Python script an interpreter runs", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run"))
			path := filepath.Join(h.home, "tools", "audit.py")
			writeRemovedFixture(t, path, "import os, sys\nos.execv(os.path.join(os.environ[\"HOME\"], \"lib\", \"run\"), sys.argv)\n", 0o600)
			return "/usr/bin/python3 " + path, []string{path, link}
		}},
		{"a wrapper that puts a directory on PATH", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "oh-relay"))
			path := wrapper(t, h, "PATH=/usr/bin:"+filepath.Dir(link)+"\nexport PATH\nexec oh-relay \"$@\"\n")
			return path, []string{path, link}
		}},
		{"a directory that holds a symlink", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "run"))
			return "/bin/ls " + filepath.Dir(link), []string{link}
		}},
		{"$HOME", func(t *testing.T, h *openHandsHarness) (string, []string) {
			return "$HOME/.defenseclaw/hooks/" + removedOpenHandsHookScript, nil
		}},
		{"~", func(t *testing.T, h *openHandsHarness) (string, []string) {
			return "~/.defenseclaw/hooks/" + removedOpenHandsHookScript, nil
		}},
		{"a doubled path", func(t *testing.T, h *openHandsHarness) (string, []string) {
			return filepath.Join(h.dataDir, "hooks") + "//" + removedOpenHandsHookScript, nil
		}},
		{"a command found on PATH", func(t *testing.T, h *openHandsHarness) (string, []string) {
			return "oh-audit", nil
		}},
		{"a relative path", func(t *testing.T, h *openHandsHarness) (string, []string) {
			return "bin/oh-audit", nil
		}},
		{"a shell list", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "hooks-of-mine", "audit"))
			return "/bin/true; " + link, []string{link}
		}},
		// Review fixes (G-deadcode loop round 2): an option or argument the
		// program runs (env -S, --split-string, -m, --require, a number
		// found on PATH, a command line split at its blanks, a list, a
		// shell's own -l) was ruled out as a plain option or a path that is
		// not there.
		{"env -S that runs a command found on PATH", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "relay"))
			return "/usr/bin/env -Srelay", []string{link}
		}},
		{"env --split-string that runs a command found on PATH", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "relay"))
			return "/usr/bin/env --split-string=relay", []string{link}
		}},
		{"env -S with its command line in the next word", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "relay"))
			return "/usr/bin/env -S '/usr/bin/env relay'", []string{link}
		}},
		{"env -S with its command line attached", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "relay"))
			return "/usr/bin/env '-S/usr/bin/env relay'", []string{link}
		}},
		{"--split-string with an absolute command line", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "relay"))
			return "/usr/bin/env '--split-string=/usr/bin/env relay'", []string{link}
		}},
		{"an option whose list names a command", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "relay"))
			return "/usr/bin/env --list=/dev/null,relay", []string{link}
		}},
		{"an interpreter option that runs a module", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "relay"))
			return "/usr/bin/python3 -mrelay", []string{link}
		}},
		{"an option that names a module to load", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "relay"))
			return "/usr/bin/node --require=relay", []string{link}
		}},
		{"a number found on PATH", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "30"))
			return "/usr/bin/env 30", []string{link}
		}},
		{"a command that is a number found on PATH", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "30"))
			return "30", []string{link}
		}},
		{"a login shell", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "relay"))
			profile := filepath.Join(h.home, ".profile")
			writeRemovedFixture(t, profile, link+"\n", 0o600)
			path := wrapper(t, h, "exit 0\n")
			return "/bin/sh -l " + path, []string{link, profile, path}
		}},
		{"a login shell that env runs", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "relay"))
			profile := filepath.Join(h.home, ".profile")
			writeRemovedFixture(t, profile, link+"\n", 0o600)
			path := wrapper(t, h, "exit 0\n")
			return "/usr/bin/env -i /bin/sh --login " + path, []string{link, profile, path}
		}},
		// Review fixes (G-deadcode loop round 3): a file with a NUL byte
		// was taken for a program and ruled out by the names in its bytes.
		// But a shell reads a script that holds one, and runs as a script
		// a file the system cannot load; only machine code the loader runs
		// is a program now.
		{"a shell script with a NUL byte that runs a symlink", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "relay"))
			path := filepath.Join(h.home, "audit")
			writeRemovedFixture(t, path, "#!/bin/sh\n: \x00\nexec "+link+" \"$@\"\n", 0o700)
			return "/bin/sh " + path, []string{path, link}
		}},
		{"a script with a NUL byte and no #! line", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "relay"))
			path := filepath.Join(h.home, "audit")
			writeRemovedFixture(t, path, "\x00\nexec "+link+"\n", 0o700)
			return path, []string{path, link}
		}},
		{"a script with a NUL byte after the command", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "relay"))
			path := wrapper(t, h, link+"\n# \x00\n")
			return path, []string{path, link}
		}},
		{"a wrapper that runs a script with a NUL byte", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "relay"))
			inner := filepath.Join(h.home, "lib", "inner")
			writeRemovedFixture(t, inner, "#!/bin/sh\n: \x00\nexec "+link+"\n", 0o700)
			path := wrapper(t, h, "exec "+inner+" \"$@\"\n")
			return path, []string{path, inner, link}
		}},
		{"a script behind an ELF magic number", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "relay"))
			path := filepath.Join(h.home, "audit")
			writeRemovedFixture(t, path, "\x7fELF\x02\x01\x01\x00\x00\nexec "+link+"\n", 0o700)
			return "/bin/sh " + path, []string{path, link}
		}},
		{"a script behind an image this system does not load", func(t *testing.T, h *openHandsHarness) (string, []string) {
			link := linkRemovedScript(t, h, filepath.Join(h.home, "relay"))
			path := filepath.Join(h.home, "audit")
			writeRemovedFixture(t, path, string(removedTestImage(t, "windows"))+"\nexec "+link+"\n", 0o700)
			return path, []string{path, link}
		}},
		// Review fixes (G-deadcode loop round 4): a shell reads startup
		// files the command does not show with no option too (zsh, csh,
		// fish, the file BASH_ENV or ENV names), sudo -i starts a login
		// shell, and a wrapper starts one through its #! line (#!/bin/sh -l,
		// env -S bash -l, zsh, a variable env sets) or a command in it
		// (exec /bin/sh -l, bash -l, $SHELL, sudo -i, or a shell given the
		// hook's own -l).
		{"zsh, which reads .zshenv", startupRun(".zshenv", "/bin/zsh")},
		{"zsh that env runs", startupRun(".zshenv", "/usr/bin/env /bin/zsh")},
		{"csh, which reads .cshrc", startupRun(".cshrc", "/bin/csh")},
		{"fish, which reads config.fish", startupRun(".config/fish/config.fish", "/usr/bin/fish")},
		{"sudo -i, which starts a login shell", startupRun(".profile", "/usr/bin/sudo -i")},
		{"script, which runs $SHELL", startupRun(".zshenv", "/usr/bin/script")},
		{"a shell under another name", func(t *testing.T, h *openHandsHarness) (string, []string) {
			// The system's bash (a program in a shell directory) and a hard
			// link to it under another name.
			command, made := startupRun(".profile", "")(t, h)
			system := filepath.Join(h.home, "system-bin")
			bash := filepath.Join(system, "bash")
			writeRemovedFixture(t, bash, string(removedTestImage(t, runtime.GOOS)), 0o700)
			previous := removedShellDirs
			removedShellDirs = append([]string{system}, previous...)
			t.Cleanup(func() { removedShellDirs = previous })
			shell := filepath.Join(h.home, "bin", "audit-runner")
			if err := os.MkdirAll(filepath.Dir(shell), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(bash, shell); err != nil {
				t.Fatal(err)
			}
			return shell + " -l" + command, append(made, bash, shell)
		}},
		{"bash with BASH_ENV set", func(t *testing.T, h *openHandsHarness) (string, []string) {
			command, made := startupRun(".bashenv", "/bin/bash")(t, h)
			t.Setenv("BASH_ENV", made[1])
			return command, made
		}},
		{"bash with a BASH_ENV the shell expands", func(t *testing.T, h *openHandsHarness) (string, []string) {
			command, made := startupRun(".bashenv", "/bin/bash")(t, h)
			t.Setenv("BASH_ENV", "$HOME/.bashenv")
			return command, made
		}},
		{"a Korn shell with ENV set", func(t *testing.T, h *openHandsHarness) (string, []string) {
			command, made := startupRun(".kshrc", "/bin/ksh")(t, h)
			t.Setenv("ENV", made[1])
			return command, made
		}},
		{"a #! line that passes the shell -l", startupWrapper(".profile", "#!/bin/sh -l\nexit 0\n")},
		{"a #! line that runs bash -l through env -S", startupWrapper(".bash_profile", "#!/usr/bin/env -S bash -l\nexit 0\n")},
		{"a #! line that runs zsh", startupWrapper(".zshenv", "#!/bin/zsh\nexit 0\n")},
		{"a #! line that sets BASH_ENV through env", startupWrapper(".bashenv", "#!/usr/bin/env BASH_ENV=.bashenv bash\nexit 0\n")},
		{"a wrapper that runs a login shell", startupWrapper(".profile", "#!/bin/sh\nexec /bin/sh -l -c true\n")},
		{"a wrapper that runs bash -l found on PATH", startupWrapper(".bash_profile", "#!/bin/sh\nexec bash -l -c true\n")},
		{"a wrapper that runs $SHELL", startupWrapper(".zshenv", "#!/bin/sh\nexec \"$SHELL\" -c true\n")},
		{"a wrapper that runs sudo -i", startupWrapper(".profile", "#!/bin/sh\nexec sudo -i true\n")},
		{"a wrapper that gives a shell the hook's -l", func(t *testing.T, h *openHandsHarness) (string, []string) {
			made := startup(t, h, ".profile", "#!/bin/sh\nexec /bin/sh \"$@\"\n")
			return made[0] + " -l", made
		}},
	} {
		for _, back := range []bool{false, true} {
			mode := "put back by the cleanup"
			if back {
				mode = "already back to the saved copy"
			}
			t.Run(tc.name+", "+mode, func(t *testing.T) {
				h := newOpenHandsHarness(t, false)
				command, made := tc.command(t, h)
				saved := openHandsHooksRunning(t, "/usr/local/bin/audit-hook", command)
				h.setUpOver(t, saved, back)
				before := h.state(t)
				for path, body := range removedSnapshot(t, made...) {
					before[path] = body
				}
				for run := 1; run <= 2; run++ {
					h.notices.Reset()
					if err := h.teardown(); err != nil {
						t.Fatalf("Teardown run %d = %v, want the state left for manual cleanup", run, err)
					}
					requireRemovedSnapshot(t, "a teardown that cannot rule out a hook it puts back", before)
					h.requirePeerUnchanged(t)
					notice := h.notices.String()
					if got := strings.Count(notice, "WARNING"); got != 1 || !strings.Contains(notice, h.hooksPath) || !strings.Contains(notice, h.script) {
						t.Fatalf("run %d printed %d warnings, want one naming %s and %s:\n%s", run, got, h.hooksPath, h.script, notice)
					}
					if record, ok := h.manualRecord(t, removedOpenHandsID); !ok || !record.lists(h.hooksPath) || !record.lists(h.script) {
						t.Fatalf("manual cleanup record = %+v, %v; want hooks.json and the script", record, ok)
					}
					if err := h.verify(); err != nil {
						t.Fatalf("VerifyClean with the steps recorded: %v", err)
					}
				}
				if err := os.Remove(removedCleanupRecordPath(h.dataDir, removedOpenHandsID)); err != nil {
					t.Fatal(err)
				}
				if err := h.verify(); err == nil || !strings.Contains(err.Error(), "openhands cleanup incomplete") {
					t.Fatalf("VerifyClean without the record = %v, want the cleanup named incomplete", err)
				}

				// The user deletes the script: nothing can run it any more.
				if err := os.Remove(h.script); err != nil {
					t.Fatal(err)
				}
				h.notices.Reset()
				if err := h.teardown(); err != nil {
					t.Fatalf("Teardown after the manual step: %v", err)
				}
				if h.notices.Len() != 0 {
					t.Fatalf("finished teardown printed: %s", h.notices)
				}
				h.noScript = true
				h.requireDone(t)
				requireRemovedSnapshot(t, "teardown", map[string]string{h.hooksPath: saved})
			})
		}
	}
}

// A saved hooks.json whose every command is ruled out (a path that is not
// there, a plain wrapper, an interpreter with a plain script, a quoted path,
// a binary) is put back and the script becomes the tombstone with no warning.
func TestRemovedOpenHandsTeardownTombstonesWhenEverySavedHookIsRuledOut(t *testing.T) {
	for _, back := range []bool{false, true} {
		t.Run(map[bool]string{false: "put back by the cleanup", true: "already back to the saved copy"}[back], func(t *testing.T) {
			h := newOpenHandsHarness(t, false)
			plain := filepath.Join(h.home, "tools", "audit.sh")
			writeRemovedFixture(t, plain, "#!/bin/sh\n# audit every tool call\necho audited >&2\nexit 0\n", 0o700)
			spaced := filepath.Join(h.home, "my hooks", "audit.sh")
			writeRemovedFixture(t, spaced, "#!/usr/bin/env sh\nexit 0\n", 0o700)
			compiled := filepath.Join(h.home, "tools", "audit-bin")
			writeRemovedFixture(t, compiled, string(removedTestImage(t, runtime.GOOS))+"/usr/lib/x\x00", 0o700)
			// A wrapper that runs a quoted path with a blank (checked whole,
			// and the rest of the string is part of it), a URL and /dev/null.
			// BASH_ENV names a plain file: bash reads it, and it runs nothing.
			bashEnv := filepath.Join(h.home, ".bashenv")
			writeRemovedFixture(t, bashEnv, "umask 077\n", 0o600)
			t.Setenv("BASH_ENV", bashEnv)
			quoted := filepath.Join(h.home, "tools", "run-quoted.sh")
			writeRemovedFixture(t, quoted, "#!/bin/sh\n# runs my audit hook\ncurl -fsS http://127.0.0.1:9/audit || true\nexec \""+spaced+"\" --audit \"$@\" 2>/dev/null\n", 0o700)
			saved := openHandsHooksRunning(t,
				"/usr/local/bin/audit-hook",
				plain,
				"/bin/sh "+plain+" --audit -x --log="+filepath.Join(h.home, "tools", "audit.log"),
				"/bin/bash "+plain,
				"'"+spaced+"'",
				compiled+" --config="+filepath.Join(h.home, "tools", "missing.toml"),
				compiled+" -v --paths=/dev/null,"+filepath.Join(h.home, "tools", "missing.d")+" /dev/null",
				quoted,
			)
			h.setUpOver(t, saved, back)
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if h.notices.Len() != 0 {
				t.Fatalf("a clean teardown printed: %s", h.notices)
			}
			h.requireDone(t)
			requireRemovedSnapshot(t, "teardown", map[string]string{h.hooksPath: saved})
		})
	}
}

// removedTestImage is the smallest program the loader of goos takes: an ELF
// executable header (Linux and the other Unix systems), a universal Mach-O
// executable (macOS) or a PE header (Windows).
func removedTestImage(t *testing.T, goos string) []byte {
	t.Helper()
	var b bytes.Buffer
	write := func(order binary.ByteOrder, v interface{}) {
		if err := binary.Write(&b, order, v); err != nil {
			t.Fatal(err)
		}
	}
	switch goos {
	case "windows":
		dos := make([]byte, 64)
		copy(dos, "MZ")
		binary.LittleEndian.PutUint32(dos[0x3c:], 64)
		b.Write(dos)
		b.WriteString("PE\x00\x00")
		// The fixed part of a PE32+ optional header, no data directories.
		optional := make([]byte, 112)
		binary.LittleEndian.PutUint16(optional, 0x20b)
		write(binary.LittleEndian, struct {
			Machine, Sections          uint16
			Time, Symbols, SymbolCount uint32
			OptionalHeaderSize, Flags  uint16
		}{Machine: 0x8664, OptionalHeaderSize: uint16(len(optional)), Flags: 0x0002})
		b.Write(optional)
	case "darwin":
		var thin bytes.Buffer
		// One LC_UUID load command.
		uuid := make([]byte, 24)
		binary.LittleEndian.PutUint32(uuid, 0x1b)
		binary.LittleEndian.PutUint32(uuid[4:], uint32(len(uuid)))
		if err := binary.Write(&thin, binary.LittleEndian, macho.FileHeader{Magic: macho.Magic64, Cpu: macho.CpuArm64, Type: macho.TypeExec, Ncmd: 1, Cmdsz: uint32(len(uuid))}); err != nil {
			t.Fatal(err)
		}
		thin.Write(make([]byte, 4))
		thin.Write(uuid)
		write(binary.BigEndian, []uint32{macho.MagicFat, 1, uint32(macho.CpuArm64), 0, 64, uint32(thin.Len()), 0})
		b.Write(make([]byte, 64-b.Len()))
		b.Write(thin.Bytes())
	default:
		// An ELF header and one PT_LOAD program header that maps it.
		header := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
			Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: 1}
		copy(header.Ident[:], elf.ELFMAG)
		header.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
		header.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
		header.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
		write(binary.LittleEndian, header)
		write(binary.LittleEndian, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Filesz: 120, Memsz: 120, Align: 0x1000})
	}
	return b.Bytes()
}

// Only machine code that this system's loader runs is a program the check
// rules out by its bytes: an image for another system, a header that does
// not parse, a header the loader refuses (no segment, no load command, no
// optional header) and an object file are run, if at all, as shell scripts.
func TestRemovedLoadableImageIsMachineCodeThisSystemRuns(t *testing.T) {
	changed := func(goos string, at int, change func([]byte)) []byte {
		image := removedTestImage(t, goos)
		change(image[at:])
		return image
	}
	images := map[string][]byte{
		"ELF":    removedTestImage(t, "linux"),
		"Mach-O": removedTestImage(t, "darwin"),
		"PE":     removedTestImage(t, "windows"),
		"ELF object": changed("linux", 16, func(b []byte) {
			binary.LittleEndian.PutUint16(b, uint16(elf.ET_REL))
		}),
		"ELF header with no segment": removedTestImage(t, "linux")[:64],
		"ELF with no loadable segment": changed("linux", 64, func(b []byte) {
			binary.LittleEndian.PutUint32(b, uint32(elf.PT_NOTE))
		}),
		"Mach-O object": changed("darwin", 64+12, func(b []byte) {
			binary.LittleEndian.PutUint32(b, uint32(macho.TypeObj))
		}),
		"Mach-O header with no load command": changed("darwin", 64+16, func(b []byte) {
			copy(b, make([]byte, 8))
		}),
		"PE with no optional header": changed("windows", 64+4+16, func(b []byte) {
			binary.LittleEndian.PutUint16(b, 0)
		}),
		"ELF magic number only": []byte("\x7fELF\x02\x01\x01\x00\x00\nexec /tmp/relay\n"),
		"MZ only":               []byte("MZ\x00\nexec /tmp/relay\n"),
		"shell script":          []byte("#!/bin/sh\n: \x00\nexec /tmp/relay\n"),
	}
	for _, tc := range []struct {
		goos, loads string
	}{{"linux", "ELF"}, {"freebsd", "ELF"}, {"darwin", "Mach-O"}, {"windows", "PE"}} {
		for name, image := range images {
			if got, want := removedLoadableImage(bytes.NewReader(image), tc.goos), name == tc.loads; got != want {
				t.Errorf("removedLoadableImage(%s) on %s = %v, want %v", name, tc.goos, got, want)
			}
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
// read through a link: a link to a hooks file whose hook may run the script
// keeps the script, and a link to one that runs nothing lets the cleanup
// finish (review loop round 4).
func TestRemovedOpenHandsTeardownReadsAnUnrecordedHooksFileThroughALink(t *testing.T) {
	h := newOpenHandsHarness(t, false)
	h.setUp(t, true)
	target := filepath.Join(h.home, "dotfiles", "hooks.json")
	link := linkRemovedScript(t, h, filepath.Join(h.home, "bin", "oh-audit"))
	writeRemovedFixture(t, target, openHandsHooksRunning(t, link), 0o600)
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
	for path, body := range removedSnapshot(t, workspace, target, link) {
		before[path] = body
	}
	if err := h.teardown(); err != nil {
		t.Fatalf("Teardown = %v, want the state left for manual cleanup", err)
	}
	requireRemovedSnapshot(t, "a teardown with a linked hooks file that may run the script", before)
	if record, ok := h.manualRecord(t, removedOpenHandsID); !ok || !record.lists(workspace) || !record.lists(h.script) {
		t.Fatalf("manual cleanup record = %+v, %v; want %s and the script", record, ok, workspace)
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

// Review loop round 4 (G-deadcode): the one saved hook runs a login shell
// (/bin/sh -l) over a plain script and ~/.profile runs a link to the hook
// script. The shell's -l is its own option, so the hook may run the script:
// nothing is put back and the script is not made the tombstone.
func TestRemovedOpenHandsTeardownKeepsALoginShellHookAlone(t *testing.T) {
	for _, back := range []bool{false, true} {
		t.Run(map[bool]string{false: "put back by the cleanup", true: "already back to the saved copy"}[back], func(t *testing.T) {
			h := newOpenHandsHarness(t, false)
			link := linkRemovedScript(t, h, filepath.Join(h.home, "lib", "relay"))
			profile := filepath.Join(h.home, ".profile")
			writeRemovedFixture(t, profile, link+"\n", 0o600)
			plain := filepath.Join(h.home, "tools", "plain.sh")
			writeRemovedFixture(t, plain, "exit 0\n", 0o700)
			saved := openHandsHooksRunning(t, "/bin/sh -l "+plain)
			h.setUpOver(t, saved, back)
			before := h.state(t)
			for path, body := range removedSnapshot(t, link, profile, plain) {
				before[path] = body
			}
			if err := h.teardown(); err != nil {
				t.Fatalf("Teardown = %v, want the state left for manual cleanup", err)
			}
			requireRemovedSnapshot(t, "a teardown that cannot rule out a login shell hook", before)
			if notice := h.notices.String(); strings.Count(notice, "WARNING") != 1 || !strings.Contains(notice, h.script) {
				t.Fatalf("notice = %q, want one warning naming %s", notice, h.script)
			}
		})
	}
}

// removedShellText reads a #! script only when its shell is one the check
// reads and the line gives it no option and sets no variable.
func TestRemovedShellTextReadsOnlyAPlainShellLine(t *testing.T) {
	for _, tc := range []struct {
		text, interpreter string
		ok                bool
	}{
		{"#!/bin/sh\n", "/bin/sh", true},
		{"#!/usr/bin/env sh\n", "sh", true},
		{"#!/usr/bin/env -i bash\n", "bash", true},
		{"#!/bin/sh -l\n", "", false},
		{"#!/bin/bash -e\n", "", false},
		{"#!/usr/bin/env -S bash -l\n", "", false},
		{"#!/usr/bin/env BASH_ENV=/tmp/x bash\n", "", false},
		{"#!/usr/bin/env ENV=/tmp/x sh\n", "", false},
		{"#!/bin/zsh\n", "/bin/zsh", false},
		{"#!/usr/bin/env\n", "", false},
		{"#!/usr/bin/python3\n", "/usr/bin/python3", false},
		{"exit 0\n", "", true},
	} {
		interpreter, ok := removedShellText("/tmp/audit", []byte(tc.text))
		if interpreter != tc.interpreter || ok != tc.ok {
			t.Errorf("removedShellText(%q) = %q, %v; want %q, %v", tc.text, interpreter, ok, tc.interpreter, tc.ok)
		}
	}
}
