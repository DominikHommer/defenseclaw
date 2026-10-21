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
// set up OpenHands puts its hooks.json back the way that setup found it,
// instead of only forgetting the connector, so OpenHands does not keep
// calling a hook route that no longer exists.
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
	operator := `{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/audit-hook"}]}]}`
	writeRetiredFile(t, script, "#!/bin/sh\n# defenseclaw-managed-hook v1\n")
	writeRetiredSetupRecord(t, dataDir, "openhands", "config", hooksPath, []byte(operator),
		`{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"`+script+`"}]},`+
			`{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/audit-hook"}]}]}`)
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
	if string(data) != operator {
		t.Fatalf("OpenHands hooks after the upgrade = %s, want %s", data, operator)
	}
	if body, err := os.ReadFile(script); err != nil || !strings.Contains(string(body), "disabled tombstone") {
		t.Fatalf("hook script after the upgrade = %q, %v; want the disabled tombstone", body, err)
	}
}
