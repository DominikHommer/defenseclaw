// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// until 1.1: the first gateway start after an upgrade from a release that
// set up OpenHands removes its hooks instead of only forgetting the
// connector, so OpenHands does not keep calling a hook route that no longer
// exists.
func TestUpgradeTearsDownTheRemovedOpenHandsConnector(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenHands was never set up on Windows")
	}
	home := testenv.PrivateTempDir(t)
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	dataDir := filepath.Join(home, ".defenseclaw")
	script := filepath.Join(dataDir, "hooks", "openhands-hook.sh")
	hooksPath := filepath.Join(home, ".openhands", "hooks.json")
	for path, body := range map[string]string{
		script: "#!/bin/sh\n# defenseclaw-managed-hook v1\n",
		hooksPath: `{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"` + script + `"}]},` +
			`{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/audit-hook"}]}]}`,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := connector.SaveActiveConnector(dataDir, "openhands"); err != nil {
		t.Fatal(err)
	}

	opts := connector.SetupOpts{DataDir: dataDir}
	if err := teardownPreviousConnector(connector.NewDefaultRegistry(), "codex", opts, context.Background()); err != nil {
		t.Fatalf("teardown of the removed connector: %v", err)
	}
	data, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), script) || !strings.Contains(string(data), "/usr/local/bin/audit-hook") {
		t.Fatalf("OpenHands hooks after the upgrade = %s", data)
	}
}
