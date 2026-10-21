// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// docsPage returns a docs-site page as one line of words, so a reflowed
// paragraph still matches.
func docsPage(t *testing.T, name string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	raw, err := os.ReadFile(filepath.Join(repoRoot, "docs-site", "content", "docs", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(strings.Fields(string(raw)), " ")
}

// TestDocsFailModesMatchPerUserNativeDenyRender ties the fail-mode docs of
// the connectors without a fail-closed hook contract to the mode their
// per-user hooks are rendered with for a closed (default) config. The docs
// must say what this build renders: a page that promises a closed per-user
// Copilot or Antigravity hook while the render lowers it to open lets a call
// run during a gateway outage that the docs say is denied, and the reverse
// hides a protection. When the render changes, this test fails until the
// pages change with it.
func TestDocsFailModesMatchPerUserNativeDenyRender(t *testing.T) {
	copilot := CapableHookFailMode(SetupOpts{}, NewCopilotConnector(), "closed")
	antigravity := CapableHookFailMode(SetupOpts{}, NewAntigravityConnector(), "closed")
	if copilot != antigravity {
		t.Fatalf("per-user closed render: copilot %q, antigravity %q; fail-modes.mdx describes them in one row, split it", copilot, antigravity)
	}

	stayOpen := map[string][]string{
		"reference/fail-modes.mdx":             {"The generated hooks stay open even when the effective mode is `closed`."},
		"reference/connectors/copilot.mdx":     {"Copilot exposes no fail-closed hook transport.", "cannot make an unavailable hook block the agent"},
		"connectors/copilot.mdx":               {"An unreachable gateway, a timeout or a bad answer does not block the agent."},
		"reference/connectors/antigravity.mdx": {"use an event-correct no-op response in normal fail-open operation"},
		"connectors/antigravity.mdx":           {"A gateway failure lets the call run."},
	}
	promisesClosed := map[string][]string{
		"reference/fail-modes.mdx":             {"The hooks follow the effective mode on Linux, macOS and Windows: `closed` blocks `preToolUse`", "the DefenseClaw hook blocks `preToolUse` and `permissionRequest` in fail mode closed", "the DefenseClaw hook blocks `PreToolUse` in fail mode closed"},
		"reference/capability-matrix.mdx":      {"Their DefenseClaw hooks still deny a call DefenseClaw cannot check"},
		"reference/connectors/copilot.mdx":     {"is denied with Copilot's own `deny` in fail mode `closed`"},
		"connectors/copilot.mdx":               {"is denied in fail mode `closed`"},
		"reference/connectors/antigravity.mdx": {"a gateway, authentication or decoding failure denies `PreToolUse`"},
		"connectors/antigravity.mdx":           {"a gateway failure denies `PreToolUse`"},
	}
	want, refuse := stayOpen, promisesClosed
	if copilot == "closed" {
		want, refuse = promisesClosed, stayOpen
	}
	for name, phrases := range refuse {
		page := docsPage(t, name)
		for _, phrase := range phrases {
			if strings.Contains(page, phrase) {
				t.Errorf("%s says %q, but a per-user Copilot/Antigravity hook renders %q for a closed config", name, phrase, copilot)
			}
		}
	}
	if copilot == "open" {
		for name, phrases := range want {
			page := docsPage(t, name)
			for _, phrase := range phrases {
				if !strings.Contains(page, phrase) {
					t.Errorf("%s must say %q: a per-user Copilot/Antigravity hook renders open for a closed config", name, phrase)
				}
			}
		}
	}

	// Hermes is the per-user connector whose hook keeps closed although the
	// agent has no fail-closed contract (hookBlocksItsOwnFailures).
	hermes := CapableHookFailMode(SetupOpts{}, NewHermesConnector(), "closed")
	hermesRow := "Its own hook has no fail-closed surface, but the DefenseClaw hook follows the effective mode"
	if got := strings.Contains(docsPage(t, "reference/fail-modes.mdx"), hermesRow); got != (hermes == "closed") {
		t.Errorf("fail-modes.mdx Hermes row says the hook follows a closed mode = %v, but the per-user Hermes render is %q", got, hermes)
	}
}
