// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
)

// A managed user runs the setup the enrollment reports, on a host with no
// Python CLI: it writes the guarded editor entry into the user settings file
// (JSONC, other entries and the leading comment kept) and a contract lock the
// guard accepts, and a second entry of the same editor re-pins the first
// lock, whose settings digest it changed (GAP-0254).
// A program of that name in the current folder is refused in words, not as
// "not found" (GAP-0734).
func TestResolveACPExecutableNamesTheCurrentFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH lookup of the current folder differs on Windows")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dcfakeagent"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("PATH", ".")
	if _, err := resolveACPExecutable("dcfakeagent", "Fake Agent"); err == nil || !strings.Contains(err.Error(), "current folder") {
		t.Fatalf("err = %v, want the current-folder refusal", err)
	}
}

// A changed editor command cannot be reported as a completed managed setup.
func TestEnterpriseACPSetupStateRejectsChangedEditorCommand(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	settings := filepath.Join(home, ".config", "zed", "settings.json")
	lockPath := acpContractLockPath(dataDir, "zed", "kiro")
	tokenPath, err := acp.EnterpriseUserTokenPath(dataDir, "zed", "kiro")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	guard := filepath.Join(home, "defenseclaw-acp")
	writeEntry := func(command string) {
		t.Helper()
		document := map[string]any{"agent_servers": map[string]any{
			acpManagedEntryName("kiro"): map[string]any{
				"command": command,
				"args":    []string{"--token-file", tokenPath, "--contract-lock", lockPath},
			},
		}}
		body, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(settings, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeEntry(guard)
	digest, err := acp.ClientEntrySHA256(settings, "zed", "kiro")
	if err != nil {
		t.Fatal(err)
	}
	lock := acp.RuntimeContractLock{}
	lock.Client.ConfigPath = settings
	lock.Client.ConfigSHA256 = acp.EntryDigestPrefix + digest
	lock.Guard.Path = guard
	lock.Profile, lock.Mode = "locked", "action"
	body, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if done, note := enterpriseACPSetupState(dataDir, home, "zed", "kiro", "locked", "action"); !done {
		t.Fatalf("unmodified setup is stale: %s", note)
	}
	writeEntry(filepath.Join(home, "another-command"))
	if done, note := enterpriseACPSetupState(dataDir, home, "zed", "kiro", "locked", "action"); done || note == "" {
		t.Fatalf("changed command reported as setup done: done=%v note=%q", done, note)
	}
}

// The setup command of an enrollment a newer one replaced is refused and
// changes nothing: it overwrote the working entry and lock (GAP-0733).
func TestEnterpriseACPUserSetupRefusesAReplacedEnrollment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows editor settings path is covered by the live managed run")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	stubEnterpriseACPGuardCustody(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	credential, err := acp.EnsureEnterpriseCredential(t.TempDir(), "uid:1001", "zed", "kiro", "act")
	if err != nil {
		t.Fatal(err)
	}
	tokenPath, err := acp.PublishEnterpriseUserToken(dataDir, "zed", "kiro", credential.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeEnterpriseACPUserEnrollment(tokenPath, "act", "action"); err != nil {
		t.Fatal(err)
	}
	guard, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	agent := filepath.Join(home, "kiro-cli")
	if err := os.WriteFile(agent, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	setup := func(profile string) error {
		_, err := setupEnterpriseACPUserFiles(enterpriseACPUserSetup{
			client: "zed", agent: "kiro", profile: profile, mode: acp.ModeObserve, dataDir: dataDir, guard: guard,
			agentBinary: agent, gatewayURL: "http://127.0.0.1:18970/api/v1/acp/evaluate",
			rerun: func(profile string, mode acp.Mode) string {
				return "setup --profile " + profile + " --mode " + string(mode)
			},
		})
		return err
	}
	if err := setup("obs"); err == nil || !strings.Contains(err.Error(), "enrolled you for zed/kiro in profile act") ||
		!strings.Contains(err.Error(), "Run: setup --profile act --mode action") {
		t.Fatalf("the setup of a replaced enrollment: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "zed", "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("a refused setup wrote the editor settings: %v", err)
	}
	if err := setup("act"); err != nil {
		t.Fatalf("the setup of the current enrollment: %v", err)
	}
}

// stubEnterpriseACPGuardCustody accepts the test binary as the guard: it is
// not in an administrator-owned directory.
func stubEnterpriseACPGuardCustody(t *testing.T) {
	t.Helper()
	old := enterpriseACPGuardCustody
	enterpriseACPGuardCustody = func(string) error { return nil }
	t.Cleanup(func() { enterpriseACPGuardCustody = old })
}

// A managed setup pins only the administrator-owned guard: a copy in the home
// is refused and nothing is written (GAP-0426).
func TestEnterpriseACPUserSetupRefusesAGuardTheUserOwns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows custody check is covered by the live managed run")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	dataDir := filepath.Join(home, ".defenseclaw")
	credential, err := acp.EnsureEnterpriseCredential(t.TempDir(), "uid:1001", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acp.PublishEnterpriseUserToken(dataDir, "zed", "kiro", credential.Token); err != nil {
		t.Fatal(err)
	}
	guard := filepath.Join(home, "my-acp-guard")
	agent := filepath.Join(home, "kiro-cli")
	for _, path := range []string{guard, agent} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_, err = setupEnterpriseACPUserFiles(enterpriseACPUserSetup{
		client: "zed", agent: "kiro", profile: "locked", mode: acp.ModeObserve, dataDir: dataDir, guard: guard,
		agentBinary: agent, gatewayURL: "http://127.0.0.1:18970/api/v1/acp/evaluate",
	})
	if err == nil || !strings.Contains(err.Error(), "not the administrator-owned DefenseClaw ACP guard") {
		t.Fatalf("a guard in the home was accepted: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".config", "zed", "settings.json")); !os.IsNotExist(statErr) {
		t.Fatalf("a refused setup wrote the editor settings: %v", statErr)
	}
}
