// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func writePurgeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func purgeTestBackups(t *testing.T, home string) []string {
	t.Helper()
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	var backups []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), perUserBackupPrefix) {
			backups = append(backups, filepath.Join(home, entry.Name()))
		}
	}
	sort.Strings(backups)
	return backups
}

// #1299: a managed uninstall --purge deleted the ~/.defenseclaw of an
// account that had its own per-user install before the managed deployment
// enrolled it, with no backup. The purge now moves that install's data to a
// ~/.defenseclaw-backup-<UTC time> folder first and still removes
// ~/.defenseclaw; what the enrollment wrote and the install's runtime are
// not kept.
func TestPurgeUserStateBacksUpAPerUserInstallFromBeforeTheEnrollment(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	kept := map[string]string{
		"config.yaml":                 "gateway: {}\n",
		".env":                        "SAMPLE_KEY=placeholder\n",
		"audit.db":                    "sqlite",
		"policies/custom.rego":        "package custom\n",
		"previous/data/audit.db":      "old",
		"foreign-hooks-backup/a.json": "{}",
	}
	for rel, body := range kept {
		writePurgeTestFile(t, filepath.Join(dataDir, rel), body)
	}
	dropped := []string{"hooks/claude-code-hook.sh", "hooks/.token-claudecode", ".venv/bin/defenseclaw", ".uv/cache/x", "session-facts.json", "watcher-created-dirs.json", "hook_contract_lock.json"}
	for _, rel := range dropped {
		writePurgeTestFile(t, filepath.Join(dataDir, rel), "managed")
	}
	summary, err := PurgeUserState(context.Background(), InstallOptions{
		UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("PurgeUserState: %v", err)
	}
	if !summary.Data || !summary.Backup {
		t.Fatalf("summary = %+v, want the data purged and backed up", summary)
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("~/.defenseclaw stayed: %v", err)
	}
	backups := purgeTestBackups(t, home)
	if len(backups) != 1 {
		t.Fatalf("backups = %v, want one", backups)
	}
	backup := backups[0]
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("backup folder %s: %v %v", backup, info, err)
	}
	for rel, body := range kept {
		got, err := os.ReadFile(filepath.Join(backup, rel))
		if err != nil || string(got) != body {
			t.Fatalf("backup lost %s: %q %v", rel, got, err)
		}
	}
	for _, rel := range dropped {
		top := strings.SplitN(rel, "/", 2)[0]
		if _, err := os.Lstat(filepath.Join(backup, top)); !os.IsNotExist(err) {
			t.Fatalf("backup kept %s, which the purge removes: %v", top, err)
		}
	}
	note, err := os.ReadFile(filepath.Join(backup, perUserBackupNote))
	if err != nil || !strings.Contains(string(note), "move\nthese files back into ~/.defenseclaw") {
		t.Fatalf("backup note: %q %v", note, err)
	}
}

// A home with only what the managed enrollment wrote (no per-user install)
// gets no backup folder: the purge removes it all, as before.
func TestPurgeUserStateKeepsNoBackupOfManagedOnlyState(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	for _, rel := range []string{"hooks/codex-hook.sh", "session-facts.json", "foreign-hooks-backup/codex/x.json", "logs/hook.log"} {
		writePurgeTestFile(t, filepath.Join(dataDir, rel), "managed")
	}
	summary, err := PurgeUserState(context.Background(), InstallOptions{
		UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("PurgeUserState: %v", err)
	}
	if !summary.Data || summary.Backup {
		t.Fatalf("summary = %+v, want the data purged without a backup", summary)
	}
	if backups := purgeTestBackups(t, home); len(backups) != 0 {
		t.Fatalf("a managed-only state got a backup: %v", backups)
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("~/.defenseclaw stayed: %v", err)
	}
}

// Two purges in the same second get two backup folders, and a moved file
// named like the note is never replaced by it.
func TestBackupPerUserInstallNeverReplacesAnEarlierBackupOrAMovedFile(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for round, body := range []string{"first", "second"} {
		writePurgeTestFile(t, filepath.Join(dataDir, "config.yaml"), body)
		writePurgeTestFile(t, filepath.Join(dataDir, perUserBackupNote), "the user's own "+body)
		backedUp, err := backupPerUserInstall(home, dataDir, now)
		if err != nil || !backedUp {
			t.Fatalf("round %d: backedUp=%v err=%v", round, backedUp, err)
		}
	}
	backups := purgeTestBackups(t, home)
	want := []string{
		filepath.Join(home, perUserBackupPrefix+"20261017T120000Z"),
		filepath.Join(home, perUserBackupPrefix+"20261017T120000Z-2"),
	}
	if strings.Join(backups, ",") != strings.Join(want, ",") {
		t.Fatalf("backups = %v, want %v", backups, want)
	}
	for i, body := range []string{"first", "second"} {
		if got, _ := os.ReadFile(filepath.Join(backups[i], "config.yaml")); string(got) != body {
			t.Fatalf("%s holds %q, want %q", backups[i], got, body)
		}
		if got, _ := os.ReadFile(filepath.Join(backups[i], perUserBackupNote)); string(got) != "the user's own "+body {
			t.Fatalf("the note replaced the moved file in %s: %q", backups[i], got)
		}
	}
}
