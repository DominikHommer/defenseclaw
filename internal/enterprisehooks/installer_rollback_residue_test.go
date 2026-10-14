// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A Claude Code install the machine's managed settings make useless
// (allowManagedHooksOnly) fails after Setup. Its rollback took back the hook
// registration only, so the account kept DefenseClaw's hook scripts, hook
// token and config and connector backups with no manifest row naming them,
// and uninstall --purge left them (GAP-0509). The rollback now removes what
// the install added below the data directory and keeps what was there.
func TestFailedInstallRemovesTheFilesItAdded(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	policyRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyRoot, "managed-settings.json"), []byte(`{"allowManagedHooksOnly": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	previous := connector.ClaudeCodeManagedSettingsRootOverride
	connector.ClaudeCodeManagedSettingsRootOverride = policyRoot
	t.Cleanup(func() { connector.ClaudeCodeManagedSettingsRootOverride = previous })

	install := func(home string) error {
		_, err := Install(context.Background(), InstallOptions{
			ConnectorName: "claudecode",
			UserHome:      home,
			OwnerUID:      os.Getuid(),
			OwnerGID:      os.Getgid(),
			APIAddr:       "127.0.0.1:18970",
			APIToken:      "test-token",
			AgentVersion:  "2.1.296",
			Registry:      connector.NewDefaultRegistry(),
		})
		return err
	}
	settingsBytes := []byte(`{"permissions": {"allow": ["Bash(ls)"]}}` + "\n")
	newHome := func(t *testing.T) string {
		home := newTestHome(t)
		if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), settingsBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		return home
	}
	checkFailed := func(t *testing.T, home string) {
		t.Helper()
		err := install(home)
		if err == nil || !strings.Contains(err.Error(), "allowManagedHooksOnly") {
			t.Fatalf("Install error = %v, want the managed-hooks-only refusal", err)
		}
		if got, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json")); err != nil || strings.Contains(string(got), "defenseclaw") {
			t.Fatalf("the user's Claude settings still name DefenseClaw (%v): %s", err, got)
		}
	}

	t.Run("an account without DefenseClaw state keeps none", func(t *testing.T) {
		home := newHome(t)
		checkFailed(t, home)
		if left := treeBelow(t, filepath.Join(home, ".defenseclaw")); len(left) != 0 {
			t.Fatalf("the failed install left %v", left)
		}
	})
	t.Run("what was there stays", func(t *testing.T) {
		home := newHome(t)
		dataDir := filepath.Join(home, ".defenseclaw")
		if err := os.MkdirAll(filepath.Join(dataDir, "notes"), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"session-facts.json", "notes/mine.txt"} {
			if err := os.WriteFile(filepath.Join(dataDir, name), []byte("kept"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		checkFailed(t, home)
		if left := strings.Join(treeBelow(t, dataDir), " "); left != ". notes notes/mine.txt session-facts.json" {
			t.Fatalf("after the failed install the data directory holds %q", left)
		}
	})
}

// treeBelow lists dir's entries relative to it ("." for dir), nil when dir
// does not exist.
func treeBelow(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		out = append(out, filepath.ToSlash(rel))
		return err
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// The snapshot keeps what was there, removes files and folders added after
// it, never follows a link, and removes the data directory only when it
// made it.
func TestDataDirSnapshotRemovesOnlyAdded(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(root, "data")
	snap := snapshotDataDir(dataDir)
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "hooks", "hook.sh"), []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dataDir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := snap.removeAdded(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the data directory the install made stays: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Fatalf("a link was followed: %v", err)
	}
}
