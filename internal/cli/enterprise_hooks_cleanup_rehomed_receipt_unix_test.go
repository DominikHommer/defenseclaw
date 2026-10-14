//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func copyRehomedTestTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dest := filepath.Join(to, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch {
		case entry.IsDir():
			return os.MkdirAll(dest, info.Mode().Perm())
		case entry.Type()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(target, dest)
		case entry.Type().IsRegular():
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(dest, data, info.Mode().Perm())
		default:
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}

type rehomedOpenCodeCase struct {
	fixture              *standaloneFixture
	resolver             standaloneTestResolver
	entry                enterpriseHookUserCleanup
	oldHome, currentHome string
	oldPlugin, newPlugin string
	oldReceipt           string
	oldEditedBytes       []byte
}

func setupRehomedOpenCodeCase(t *testing.T, edited, move bool) rehomedOpenCodeCase {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the per-user worker requires a non-root test account")
	}
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	previous := connector.OpenCodePluginPathOverride
	connector.OpenCodePluginPathOverride = ""
	t.Cleanup(func() { connector.OpenCodePluginPathOverride = previous })
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	homes, err := os.MkdirTemp(userHome, ".defenseclaw-rehome-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(homes) })
	if err := os.Chmod(homes, 0o700); err != nil {
		t.Fatal(err)
	}
	oldHome := filepath.Join(homes, "sample-user-old")
	currentHome := filepath.Join(homes, "sample-user-current")
	for _, home := range []string{oldHome, currentHome} {
		if err := os.Mkdir(home, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	uid, gid := os.Getuid(), os.Getgid()
	resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: currentHome}
	plugin := func(home string) string {
		return filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js")
	}
	oldPlugin := plugin(oldHome)
	oldReceipt := filepath.Join(oldHome, ".defenseclaw", "connector_backups", "opencode", "config.json")
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "opencode", UserHome: oldHome, OwnerUID: uid, OwnerGID: gid,
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
		GuardrailMode: "action", HookFailMode: "closed", AgentVersion: "1.18.33",
		Registry: connector.NewDefaultRegistry(),
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatalf("install old-home OpenCode plugin: %v", err)
	}
	receipt, err := os.ReadFile(oldReceipt)
	if err != nil || !bytes.Contains(receipt, []byte(oldPlugin)) {
		t.Fatalf("old-home receipt does not bind plugin: %v", err)
	}
	var editedBytes []byte
	if edited {
		original, err := os.ReadFile(oldPlugin)
		if err != nil {
			t.Fatal(err)
		}
		editedBytes = append(append([]byte(nil), original...), []byte("\n// operator edit\n")...)
		if err := os.WriteFile(oldPlugin, editedBytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copyRehomedTestTree(t, oldHome, currentHome)
	if move {
		if err := os.RemoveAll(oldHome); err != nil {
			t.Fatal(err)
		}
	}
	useEnterpriseHookWorkerHelper(t, "real")
	enterpriseHookWorkerRunner = runEnterpriseHookWorker
	return rehomedOpenCodeCase{
		fixture: f, resolver: resolver,
		entry: enterpriseHookUserCleanup{Connector: "opencode", User: "sample-user", UID: uid,
			UserHome: oldHome, DataDir: filepath.Join(oldHome, ".defenseclaw"), RecordedAt: time.Now().UTC().Format(time.RFC3339)},
		oldHome: oldHome, currentHome: currentHome, oldPlugin: oldPlugin,
		newPlugin: plugin(currentHome), oldReceipt: oldReceipt, oldEditedBytes: editedBytes,
	}
}

func TestStandaloneCleanupCopiedOpenCodeReceipt(t *testing.T) {
	for _, edited := range []bool{false, true} {
		name := "pristine"
		if edited {
			name = "edited"
		}
		t.Run(name, func(t *testing.T) {
			c := setupRehomedOpenCodeCase(t, edited, false)
			var log bytes.Buffer
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &log, c.entry, c.resolver)
			if !edited {
				if outcome != enterpriseHookUserCleanupDone || err != nil {
					t.Fatalf("pristine copy cleanup = %v, %v", outcome, err)
				}
				if _, statErr := os.Lstat(c.newPlugin); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("current home still loads the copied plugin: %v", statErr)
				}
				if _, statErr := os.Lstat(c.oldPlugin); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("recorded home still loads the plugin: %v", statErr)
				}
				return
			}
			if outcome != enterpriseHookUserCleanupFailed || err == nil ||
				!strings.Contains(err.Error(), c.oldPlugin) || !strings.Contains(err.Error(), c.newPlugin) ||
				!strings.Contains(err.Error(), "stale copied receipt") {
				t.Fatalf("edited copy cleanup = %v, %v; want kept row naming both paths and remedy", outcome, err)
			}
			if data, readErr := os.ReadFile(c.newPlugin); readErr != nil || !bytes.Equal(data, c.oldEditedBytes) {
				t.Fatalf("unverified current plugin changed: %v", readErr)
			}
			if data, readErr := os.ReadFile(c.oldPlugin); readErr != nil || !bytes.Equal(data, c.oldEditedBytes) {
				t.Fatalf("operator-edited plugin changed: %v", readErr)
			}
			if _, statErr := os.Stat(c.oldReceipt); statErr != nil {
				t.Fatalf("edited plugin's receipt lost: %v", statErr)
			}
		})
	}
}

func TestStandaloneCleanupMovedOpenCodeReceipt(t *testing.T) {
	c := setupRehomedOpenCodeCase(t, false, true)
	outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, c.entry, c.resolver)
	if outcome != enterpriseHookUserCleanupDone || err != nil {
		t.Fatalf("moved home cleanup = %v, %v", outcome, err)
	}
	if _, err := os.Lstat(c.newPlugin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("moved-home plugin remains: %v", err)
	}
}

func alterCopiedPluginFirstLine(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	newline := bytes.IndexByte(data, '\n')
	if newline < 0 {
		t.Fatal("plugin has no first line")
	}
	edited := append([]byte("// operator changed the first line\n"), data[newline+1:]...)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	return edited
}

func TestStandaloneCleanupCopiedOpenCodeChangedMarkerFailsOnRetry(t *testing.T) {
	c := setupRehomedOpenCodeCase(t, false, false)
	edited := alterCopiedPluginFirstLine(t, c.newPlugin)
	for attempt := 1; attempt <= 2; attempt++ {
		outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, c.entry, c.resolver)
		if outcome != enterpriseHookUserCleanupFailed || err == nil ||
			!strings.Contains(err.Error(), c.newPlugin) || !strings.Contains(err.Error(), "remove DefenseClaw's entries") ||
			!strings.Contains(err.Error(), "stale copied receipt") {
			t.Fatalf("attempt %d = %v, %v", attempt, outcome, err)
		}
		if data, err := os.ReadFile(c.newPlugin); err != nil || !bytes.Equal(data, edited) {
			t.Fatalf("attempt %d changed the current plugin: %v", attempt, err)
		}
	}
}

func TestRemoveAllCopiedOpenCodeChangedMarkerKeepsRow(t *testing.T) {
	c := setupRehomedOpenCodeCase(t, false, false)
	edited := alterCopiedPluginFirstLine(t, c.newPlugin)
	now := time.Now()
	if err := saveEnterpriseHookUserCleanups(c.fixture.dataDir, []enterpriseHookUserCleanup{c.entry}, now); err != nil {
		t.Fatal(err)
	}
	c.fixture.writeManifest(t)
	manifest, err := enterprisehooks.LoadManifest(c.fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	var guardianLog bytes.Buffer
	if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &guardianLog, manifest,
		enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, c.resolver, now); err != nil {
		t.Fatal(err)
	}
	remaining, err := loadEnterpriseHookUserCleanups(c.fixture.dataDir)
	if err != nil || len(remaining) != 1 || !strings.Contains(guardianLog.String(), c.newPlugin) ||
		!strings.Contains(remaining[0].LastError, "rerun") {
		t.Fatalf("guardian row or path warning lost: remaining %+v, %v, log %q", remaining, err, guardianLog.String())
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{}
	skip := runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
	if report.Removed != 0 || len(report.Failed) != 1 || len(report.Pending) != 0 ||
		!strings.Contains(report.Failed[0], c.newPlugin) || !strings.Contains(report.Failed[0], "rerun") ||
		skip[c.entry.UID] != enterpriseHookPurgeSkipFailed {
		t.Fatalf("remove-all did not keep changed copy: report %+v, skip %+v", report, skip)
	}
	if data, err := os.ReadFile(c.newPlugin); err != nil || !bytes.Equal(data, edited) {
		t.Fatalf("remove-all changed current plugin: %v", err)
	}
}

func TestStandaloneCleanupCopiedCodexReceiptUsesCurrentConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the per-user worker requires a non-root test account")
	}
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	oldHome := f.home(t, "sample-codex-old", 0o700)
	currentHome := f.home(t, "sample-codex-current", 0o700)
	uid, gid := os.Getuid(), os.Getgid()
	t.Setenv("HOME", oldHome)
	t.Setenv("CODEX_HOME", "")
	previousPath := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = ""
	t.Cleanup(func() { connector.CodexConfigPathOverride = previousPath })
	oldConfig := filepath.Join(oldHome, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(oldConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "codex", UserHome: oldHome, OwnerUID: uid, OwnerGID: gid,
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
		GuardrailMode: "action", HookFailMode: "closed", AgentVersion: "codex-cli 0.142.0",
		Registry: connector.NewDefaultRegistry(),
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatalf("install Codex in recorded home: %v", err)
	}
	oldReceipt := filepath.Join(oldHome, ".defenseclaw", "connector_backups", "codex", "config.toml.json")
	if data, err := os.ReadFile(oldReceipt); err != nil || !bytes.Contains(data, []byte(oldConfig)) {
		t.Fatalf("Codex receipt does not name the recorded config: %v", err)
	}
	copyRehomedTestTree(t, oldHome, currentHome)
	currentConfig := filepath.Join(currentHome, ".codex", "config.toml")
	resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: currentHome}
	entry := enterpriseHookUserCleanup{Connector: "codex", User: "sample-user", UID: uid,
		UserHome: oldHome, DataDir: filepath.Join(oldHome, ".defenseclaw")}
	useEnterpriseHookWorkerHelper(t, "real")
	var homes []string
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		homes = append(homes, account.Home)
		return runEnterpriseHookWorker(ctx, account, request)
	}
	outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver)
	if outcome != enterpriseHookUserCleanupFailed || err == nil ||
		!strings.Contains(err.Error(), oldConfig) || !strings.Contains(err.Error(), currentConfig) ||
		!strings.Contains(err.Error(), "stale copied receipt") || len(homes) != 1 {
		t.Fatalf("unverifiable Codex copy = %v, %v, worker homes %v", outcome, err, homes)
	}
	if data, readErr := os.ReadFile(currentConfig); readErr != nil || !strings.Contains(strings.ToLower(string(data)), "defenseclaw") {
		t.Fatalf("current Codex config unexpectedly cleaned: %v, %q", readErr, data)
	}
	// Removing the stale receipt alone does not prove the copied config is
	// clean: Codex's old absolute hook references can survive its teardown.
	if err := os.RemoveAll(filepath.Join(currentHome, ".defenseclaw", "connector_backups", "codex")); err != nil {
		t.Fatal(err)
	}
	outcome, err = attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver)
	if outcome != enterpriseHookUserCleanupFailed || err == nil || !strings.Contains(err.Error(), currentConfig) || len(homes) != 3 {
		t.Fatalf("copied Codex config ended before its entries were removed: %v, %v, worker homes %v", outcome, err, homes)
	}
	if data, readErr := os.ReadFile(currentConfig); readErr != nil || !strings.Contains(strings.ToLower(string(data)), "defenseclaw") {
		t.Fatalf("copied config no longer reproduces residual entries: %v, %q", readErr, data)
	}
	// The operator removes the named entries. Only then may the row end.
	if err := os.WriteFile(currentConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outcome, err = attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver)
	if outcome != enterpriseHookUserCleanupDone || err != nil {
		t.Fatalf("Codex cleanup after removing entries = %v, %v, worker homes %v", outcome, err, homes)
	}
	if len(homes) != 5 || homes[0] != currentHome || homes[1] != currentHome || homes[2] != currentHome ||
		homes[3] != currentHome || homes[4] != oldHome {
		t.Fatalf("cleanup used unexpected homes: %v", homes)
	}
	for _, path := range []string{currentConfig, oldConfig} {
		data, err := os.ReadFile(path)
		if err != nil || strings.Contains(strings.ToLower(string(data)), "defenseclaw") {
			t.Fatalf("Codex config %s still has DefenseClaw entries: %v, %q", path, err, data)
		}
	}
}
