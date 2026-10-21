// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDocsFailModesDescribeTheLegacyHookConfigOpen ties the upgrade sentence
// of reference/fail-modes.mdx to how the per-user Windows hook reads a
// .hookcfg an earlier release wrote. While such a file's open is still read
// as open (until the gateway renders the hooks again), the page must say so
// and must not say the earlier open is treated as closed. When the reader
// stops honoring it, the page must drop the interval.
func TestDocsFailModesDescribeTheLegacyHookConfigOpen(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	raw, err := os.ReadFile(filepath.Join(repoRoot, "docs-site", "content", "docs", "reference", "fail-modes.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	page := strings.Join(strings.Fields(string(raw)), " ")

	// The shapes 1.0.0 to 1.0.3 wrote: KEY=value, version 2 with a legacy
	// fallback, and version 2 with a connector entry.
	earlier := map[string]string{
		"key-value":         "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:18970\nDEFENSECLAW_CONNECTOR=copilot\nDEFENSECLAW_FAIL_MODE=open\n",
		"v2-legacy":         `{"version":2,"gateway_addr":"127.0.0.1:18970","legacy_fail_mode":"open"}`,
		"v2-connector-open": `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"copilot":"open"}}`,
	}
	var readsOpen []string
	for shape, body := range earlier {
		path := filepath.Join(t.TempDir(), ".hookcfg")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if hookSidecarFailMode(readHookSidecar(path), "copilot") == "open" {
			readsOpen = append(readsOpen, shape)
		}
	}

	interval := "An `open` recorded there stays open in that interval, even when `config.yaml` no longer sets it."
	if len(readsOpen) > 0 {
		if !strings.Contains(page, interval) {
			t.Errorf("fail-modes.mdx must describe the legacy-open interval: the hook reads an earlier .hookcfg open as open (%v)", readsOpen)
		}
		for _, claim := range []string{
			"an open that an earlier release left in the hook config is treated as closed",
			"Hooks follow an open fail mode only when your config sets it",
		} {
			if strings.Contains(page, claim) {
				t.Errorf("fail-modes.mdx says %q, but the hook reads an earlier .hookcfg open as open (%v)", claim, readsOpen)
			}
		}
	} else if strings.Contains(page, interval) {
		t.Errorf("fail-modes.mdx still describes a legacy-open interval, but no earlier .hookcfg open is read as open")
	}
}
