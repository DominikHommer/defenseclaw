// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func copyPluginReceiptFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPluginCopiedReceiptStaysInItsOwnHome(t *testing.T) {
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	root := testenv.PrivateTempDir(t)
	oldHome, currentHome := filepath.Join(root, "sample-old"), filepath.Join(root, "sample-current")
	for _, home := range []string{oldHome, currentHome} {
		if err := os.Mkdir(home, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	previous := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = ""
	t.Cleanup(func() { OpenCodePluginPathOverride = previous })
	conn := NewOpenCodeConnector()
	plugin := func(home string) string {
		return filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js")
	}
	receipt := func(home string) string {
		return managedFileBackupPath(filepath.Join(home, ".defenseclaw"), "opencode", "config")
	}
	oldOpts := prepareOpenCodeSetupOptsForTest(t, SetupOpts{
		DataDir: filepath.Join(oldHome, ".defenseclaw"), APIAddr: "127.0.0.1:18970",
		APIToken: strings.Repeat("a", 64), HookFailMode: "closed",
	})
	if err := WithUserHomeDir(oldHome, func() error { return conn.Setup(context.Background(), oldOpts) }); err != nil {
		t.Fatal(err)
	}
	oldPlugin, err := os.ReadFile(plugin(oldHome))
	if err != nil {
		t.Fatal(err)
	}
	oldReceipt, err := os.ReadFile(receipt(oldHome))
	if err != nil {
		t.Fatal(err)
	}
	copyPluginReceiptFile(t, plugin(oldHome), plugin(currentHome))
	copyPluginReceiptFile(t, receipt(oldHome), receipt(currentHome))
	currentOpts := oldOpts
	currentOpts.DataDir = filepath.Join(currentHome, ".defenseclaw")
	if err := WithUserHomeDir(currentHome, func() error { return conn.Teardown(context.Background(), currentOpts) }); err != nil {
		t.Fatalf("current-home teardown: %v", err)
	}
	if _, err := os.Lstat(plugin(currentHome)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("copied plugin remains: %v", err)
	}
	if _, err := os.Lstat(receipt(currentHome)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("copied receipt remains: %v", err)
	}
	if data, err := os.ReadFile(plugin(oldHome)); err != nil || !bytes.Equal(data, oldPlugin) {
		t.Fatalf("other home's plugin changed: %v", err)
	}
	if data, err := os.ReadFile(receipt(oldHome)); err != nil || !bytes.Equal(data, oldReceipt) {
		t.Fatalf("other home's receipt changed: %v", err)
	}
	if err := WithUserHomeDir(oldHome, func() error { return conn.Teardown(context.Background(), oldOpts) }); err != nil {
		t.Fatalf("recorded-home teardown: %v", err)
	}
	if _, err := os.Lstat(plugin(oldHome)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recorded plugin remains: %v", err)
	}
}

func TestPluginEditedAfterSetupReportsIncompleteCleanup(t *testing.T) {
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	home := testenv.PrivateTempDir(t)
	previous := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = ""
	t.Cleanup(func() { OpenCodePluginPathOverride = previous })
	conn := NewOpenCodeConnector()
	opts := prepareOpenCodeSetupOptsForTest(t, SetupOpts{
		DataDir: filepath.Join(home, ".defenseclaw"), APIAddr: "127.0.0.1:18970",
		APIToken: strings.Repeat("a", 64), HookFailMode: "closed",
	})
	plugin := filepath.Join(home, ".config", "opencode", "plugins", "defenseclaw.js")
	if err := WithUserHomeDir(home, func() error { return conn.Setup(context.Background(), opts) }); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(plugin)
	if err != nil {
		t.Fatal(err)
	}
	edited := append(append([]byte(nil), before...), []byte("\n// operator edit\n")...)
	if err := os.WriteFile(plugin, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	err = WithUserHomeDir(home, func() error { return conn.Teardown(context.Background(), opts) })
	if err == nil || !strings.Contains(err.Error(), plugin) || !strings.Contains(err.Error(), "rerun") {
		t.Fatalf("edited managed plugin cleanup error = %v", err)
	}
	if data, err := os.ReadFile(plugin); err != nil || !bytes.Equal(data, edited) {
		t.Fatalf("operator edit changed: %v", err)
	}
	if _, err := os.Stat(managedFileBackupPath(opts.DataDir, "opencode", "config")); err != nil {
		t.Fatalf("receipt needed for retry: %v", err)
	}
}
