//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func requirePerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

// hermesStandaloneOptions installs Hermes for home, whose ~/.hermes config
// the connector resolves from HOME.
func hermesStandaloneOptions(t *testing.T, home string) InstallOptions {
	t.Helper()
	t.Setenv("HOME", home)
	config := filepath.Join(home, ".hermes", "config.yaml")
	mustMkdir(t, filepath.Dir(config), 0o700)
	if err := os.WriteFile(config, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := InstallOptions{
		ConnectorName: "hermes",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      strings.Repeat("a", 64),
		OTLPPathToken: strings.Repeat("d", 64),
		GuardrailMode: "observe",
		HookFailMode:  "open",
		Registry:      connector.NewDefaultRegistry(),
	}
	// A version with a hook contract: the guardian installs none for a
	// version without one, in any mode (GAP-0151).
	opts.AgentVersion = "0.21.5"
	return opts
}

// Unix verification read only the agent config reference and the lock, so
// a user who deleted ~/.defenseclaw/hooks/hermes-hook.sh (or edited it, or
// removed the shared _hardening.sh) left the Hermes config pointing at a
// missing or changed script while every check stayed green and no repair
// ran. The standalone verification now compares the hook runtime files
// with the digests the install recorded and with this release's render, so
// the guardian's verify-or-repair pass re-renders them, also after a package
// upgrade.
func TestStandaloneVerifyReportsAndRepairsAChangedHookScript(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("verify after the install: %v", err)
	}
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	script := filepath.Join(hooks, "hermes-hook.sh")
	original, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	repair := opts
	repair.AllowMissingHookConfigRepair = true
	for _, change := range []struct {
		name, path, want string
		apply            func(path string) error
	}{
		{"deleted hermes-hook.sh", script, "missing", os.Remove},
		{"edited hermes-hook.sh", script, "changed since it was installed", func(path string) error {
			return os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700)
		}},
		{"deleted _hardening.sh", filepath.Join(hooks, "_hardening.sh"), "missing", os.Remove},
		{"deleted inspect-tool.sh", filepath.Join(hooks, "inspect-tool.sh"), "missing", os.Remove},
		// The runtime records and the scoped token the hook script reads
		// (GAP-0671, GAP-0424): moved aside, the guardian left them
		// missing while status and verify stayed green.
		{"moved .hookcfg.hermes", filepath.Join(hooks, ".hookcfg.hermes"), "missing", os.Remove},
		{"moved .hookcfg", filepath.Join(hooks, ".hookcfg"), "missing", os.Remove},
		{"moved .hook-hermes.token", filepath.Join(hooks, ".hook-hermes.token"), "missing", os.Remove},
		{"edited .hook-hermes.token", filepath.Join(hooks, ".hook-hermes.token"), "does not hold the credential", func(path string) error {
			return os.WriteFile(path, []byte(strings.Repeat("b", 64)+"\n"), 0o600)
		}},
		// After a package upgrade the script still matches the digest
		// recorded at its last write but carries the previous release's
		// render, so the digest alone kept verification green.
		{"previous release's hermes-hook.sh", script, "differs from the rendered template", func(path string) error {
			previous := append(append([]byte{}, original...), "# previous release\n"...)
			if err := os.WriteFile(path, previous, 0o700); err != nil {
				return err
			}
			lockPath := filepath.Join(home, ".defenseclaw", "hook_contract_lock.json")
			body, err := os.ReadFile(lockPath)
			if err != nil {
				return err
			}
			var lock map[string]any
			if err := json.Unmarshal(body, &lock); err != nil {
				return err
			}
			digests := lock["connectors"].(map[string]any)["hermes"].(map[string]any)["hook_script_digests"].(map[string]any)
			digests[filepath.Base(path)] = fmt.Sprintf("sha256:%x", sha256.Sum256(previous))
			if body, err = json.Marshal(lock); err != nil {
				return err
			}
			return os.WriteFile(lockPath, body, 0o600)
		}},
	} {
		if err := change.apply(change.path); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(context.Background(), opts); err == nil || !strings.Contains(err.Error(), change.want) ||
			!strings.Contains(err.Error(), change.path) {
			t.Fatalf("%s: verify = %v, want %q for %s", change.name, err, change.want, change.path)
		}
		if _, err := Install(context.Background(), repair); err != nil {
			t.Fatalf("%s: repair: %v", change.name, err)
		}
		if _, err := Verify(context.Background(), opts); err != nil {
			t.Fatalf("%s: verify after the repair: %v", change.name, err)
		}
	}
	if repaired, err := os.ReadFile(script); err != nil || string(repaired) != string(original) {
		t.Fatalf("hermes-hook.sh after the repairs differs from the install (err=%v)", err)
	}

	// The Secure Client profile keeps its earlier verification.
	setStandaloneProfileForTest(t, false)
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("Secure Client verify changed: %v", err)
	}
}
