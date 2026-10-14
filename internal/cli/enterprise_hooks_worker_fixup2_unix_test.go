//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestEnterpriseHookWorkerConfigReferenceLine(t *testing.T) {
	for _, tc := range []struct {
		name, config, dataDir string
		wantLine              int
	}{
		{"Codex bootstrap header", "# Created by DefenseClaw installer\n # DefenseClaw only owns [hooks], [otel]\n", "", 0},
		{"comment styles", "  # /home/sample-user/.defenseclaw/hooks/codex-hook.sh\n // x-defenseclaw-source\n", "", 0},
		{"hook path", "command = '/home/sample-user/.defenseclaw/hooks/codex-hook.sh'\n", "", 1},
		{"notify bridge", "notify = ['bash', '/home/sample-user/.defenseclaw/notify-bridge.sh']\n", "", 1},
		{"data dir name at quote", "value = '.defenseclaw'\n", "", 1},
		{"data dir name at end", "value = .defenseclaw\n", "", 1},
		{"data dir name at backslash", "value = '.defenseclaw\\hooks'\n", "", 1},
		{"managed marker", "hook = 'defenseclaw-managed-hook v8'\n", "", 1},
		{"source header", "x-defenseclaw-source = 'codex'\n", "", 1},
		{"client header", "x-defenseclaw-client = 'codex-otel/1.0'\n", "", 1},
		{"native launcher", "command = 'defenseclaw-hook hook codex'\n", "", 1},
		{"plugin file", "plugin = '/home/sample-user/.config/opencode/plugins/defenseclaw.js'\n", "", 1},
		{"project uppercase", "[projects.\"/srv/work/DefenseClaw\"]\ntrust_level = 'trusted'\n", "", 0},
		{"project lowercase", "[projects.\"/home/sample-user/code/defenseclaw\"]\ntrust_level = 'trusted'\n", "", 0},
		{"similar dot directory", "value = '.defenseclaw-backup'\n", "", 0},
		{"custom data dir", "command = '/home/sample-user/custom-hooks/hooks/agent.sh'\n", "/home/sample-user/custom-hooks", 1},
		{"other data dir", "command = '/home/sample-user/custom-hooks/hooks/agent.sh'\n", "/home/sample-user/another-hooks", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, reason := enterpriseHookWorkerConfigReferenceLine([]byte(tc.config), tc.dataDir)
			if line != tc.wantLine || (line != 0 && reason == "") {
				t.Fatalf("match = %d, %q; want line %d", line, reason, tc.wantLine)
			}
		})
	}
}

func TestEnterpriseHookWorkerConfigScanKeepsReadLimits(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config.toml")
	outside := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(outside, []byte("hook = '/tmp/.defenseclaw/hooks/owned.sh'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := enterpriseHookWorkerRemainingConfigReference(home, filepath.Join(home, ".defenseclaw"), []string{outside}); got != "" {
		t.Fatalf("off-home path was read: %s", got)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if got := enterpriseHookWorkerRemainingConfigReference(home, filepath.Join(home, ".defenseclaw"), []string{path}); !strings.Contains(got, "not a regular file") {
		t.Fatalf("symlink was treated as clean: %s", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(4<<20 + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if got := enterpriseHookWorkerRemainingConfigReference(home, filepath.Join(home, ".defenseclaw"), []string{path}); !strings.Contains(got, "read limit") {
		t.Fatalf("oversized file was treated as clean: %s", got)
	}
}

func TestEnterpriseHookWorkerMatcherCoversInstallAndRemovalByConnector(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the per-user installer requires a non-root test account")
	}
	registry := connector.NewDefaultRegistry()
	// Proxy connectors are setup-only and Install refuses them before any
	// per-user hook config is written.
	setupOnly := map[string]bool{"openclaw": true, "zeptoclaw": true}
	versions := map[string]string{
		"amp": "0.0.1785334225", "codex": "codex-cli 0.142.0",
		"claudecode": "2.1.187 (Claude Code)", "opencode": "1.18.33",
		"kiro": "kiro-cli 2.24.1", "openhands": "1.16.0",
		"antigravity": "1.2.11", "omnigent": "omnigent 0.7.0",
		"hermes": "0.21.3", "cursor": "cursor 3.19.13",
		"devin": "3000.4.25", "copilot": "GitHub Copilot CLI 1.0.76",
	}
	seed := map[string]struct{ path, data string }{
		"hermes":      {".hermes/config.yaml", "{}\n"},
		"openhands":   {".openhands/hooks.json", "{}\n"},
		"antigravity": {".gemini/config/hooks.json", "{}\n"},
		"omnigent":    {".omnigent/config.yaml", "server: https://example.test\npolicy_modules: []\n"},
		"devin":       {".config/devin/config.json", "{}\n"},
	}
	for _, name := range registry.Names() {
		t.Run(name, func(t *testing.T) {
			if setupOnly[name] {
				t.Skip("proxy connector: per-user Install is setup-only")
			}
			home := t.TempDir()
			if err := os.Chmod(home, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", "")
			t.Setenv("OPENCODE_CONFIG_DIR", "")
			t.Setenv("CODEX_HOME", "")
			if name == "kiro" || name == "copilot" {
				enterprisehooks.SetStandaloneUnix(true)
				t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(false) })
			}
			if name == "kiro" {
				if err := os.MkdirAll(filepath.Join(home, ".kiro", "hooks"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if name == "copilot" {
				if err := os.MkdirAll(filepath.Join(home, ".copilot", "hooks"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if name == "omnigent" {
				previousSite := connector.OmnigentSitePackagesPathOverride
				connector.OmnigentSitePackagesPathOverride = filepath.Join(home, ".local", "lib", "python", "site-packages")
				t.Cleanup(func() { connector.OmnigentSitePackagesPathOverride = previousSite })
			}
			if fixture, ok := seed[name]; ok {
				path := filepath.Join(home, fixture.path)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(fixture.data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			opts := enterprisehooks.InstallOptions{
				ConnectorName: name, UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
				APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
				APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
				GuardrailMode: "action", HookFailMode: "closed", AgentVersion: versions[name],
				Registry: registry,
			}
			if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
				t.Fatalf("Install(%s) in a fresh user home: %v", name, err)
			}
			conn, ok := registry.Get(name)
			if !ok {
				t.Fatalf("connector %s left the registry", name)
			}
			setupOpts := connector.SetupOpts{DataDir: filepath.Join(home, ".defenseclaw"),
				ManagedEnterprise: true, AgentVersion: opts.AgentVersion}
			var paths []string
			if err := connector.WithUserHomeDir(home, func() error {
				paths = connector.CleanupConfigPathsForConnector(conn, setupOpts)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(paths) == 0 {
				t.Fatal("connector exposed no cleanup config path")
			}
			matched := false
			for _, path := range paths {
				data, err := os.ReadFile(path)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				line, _ := enterpriseHookWorkerConfigReferenceLine(data, "")
				matched = matched || line != 0
			}
			if !matched {
				t.Fatalf("matcher missed installed %s entries in %v", name, paths)
			}
			if err := enterprisehooks.RemoveUserHooks(context.Background(), opts); err != nil {
				t.Fatalf("RemoveUserHooks(%s): %v", name, err)
			}
			if remaining := enterpriseHookWorkerRemainingConfigReference(home, setupOpts.DataDir, paths); remaining != "" {
				t.Fatalf("matcher kept removed %s entries: %s", name, remaining)
			}
		})
	}
}
