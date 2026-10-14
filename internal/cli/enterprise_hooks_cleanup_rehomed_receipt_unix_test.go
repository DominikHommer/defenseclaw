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
			if _, statErr := os.Lstat(c.newPlugin); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("current home still loads the copied plugin: %v", statErr)
			}
			if !edited {
				if outcome != enterpriseHookUserCleanupDone || err != nil {
					t.Fatalf("pristine copy cleanup = %v, %v", outcome, err)
				}
				if _, statErr := os.Lstat(c.oldPlugin); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("recorded home still loads the plugin: %v", statErr)
				}
				return
			}
			if outcome != enterpriseHookUserCleanupFailed || err == nil ||
				!strings.Contains(err.Error(), c.oldPlugin) || !strings.Contains(err.Error(), "rerun") {
				t.Fatalf("edited copy cleanup = %v, %v; want kept row with plugin path and remedy", outcome, err)
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

func TestRemoveAllCopiedOpenCodeEditedReceiptKeepsRow(t *testing.T) {
	c := setupRehomedOpenCodeCase(t, true, false)
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
	if err != nil || len(remaining) != 1 || !strings.Contains(guardianLog.String(), c.oldPlugin) {
		t.Fatalf("guardian row or path warning lost: remaining %+v, %v, log %q", remaining, err, guardianLog.String())
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{}
	skip := runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
	if report.Removed != 0 || len(report.Failed) != 1 || len(report.Pending) != 0 ||
		!strings.Contains(report.Failed[0], c.oldPlugin) || !strings.Contains(report.Failed[0], "rerun") ||
		skip[c.entry.UID] != enterpriseHookPurgeSkipFailed {
		t.Fatalf("remove-all did not keep edited copy: report %+v, skip %+v", report, skip)
	}
	if data, err := os.ReadFile(c.oldPlugin); err != nil || !bytes.Equal(data, c.oldEditedBytes) {
		t.Fatalf("remove-all changed edited plugin: %v", err)
	}
}
