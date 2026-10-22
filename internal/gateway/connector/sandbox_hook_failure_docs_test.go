// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sandboxConnectorDocNames are the names the docs give each sandbox connector.
var sandboxConnectorDocNames = map[string]string{
	"amp":         "Amp",
	"antigravity": "Antigravity",
	"claudecode":  "Claude Code",
	"codex":       "Codex",
	"copilot":     "GitHub Copilot",
	"cursor":      "Cursor",
	"devin":       "Devin",
	"hermes":      "Hermes",
	"kiro":        "Kiro",
	"opencode":    "OpenCode",
}

// The fail-modes page says which sandbox hooks leave a hook-failures.jsonl
// record in the guest: the shell hooks do, and it names each plugin that
// does not. Both halves are read from the rendered overlays, so a shell hook
// that stops logging, or a plugin that starts, fails here until the page
// says so.
func TestFailModesDocNamesTheSandboxHooksThatLogFailures(t *testing.T) {
	var silent []string
	for _, tc := range sandboxGoldenTargets {
		name, ok := sandboxConnectorDocNames[tc.connector]
		if !ok {
			t.Fatalf("%s: add the connector's docs name to sandboxConnectorDocNames", tc.connector)
		}
		shell, logs := false, false
		for _, file := range renderSandboxGolden(t, tc.provider, tc.version).Files {
			shell = shell || strings.HasSuffix(file.Path, ".sh")
			logs = logs || bytes.Contains(file.Data, []byte("hook-failures.jsonl"))
		}
		if shell != logs {
			t.Fatalf("%s: shell hook set %v, writes hook-failures.jsonl %v: the page says only the shell hooks log", tc.connector, shell, logs)
		}
		if !logs {
			silent = append(silent, name)
		}
	}
	sort.Strings(silent)

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs-site", "content", "docs", "reference", "configuration", "fail-modes.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	page := strings.Join(strings.Fields(string(raw)), " ")
	claim := "In an OpenShell sandbox the shell hooks write the same record inside the guest at `" + SandboxHookLogDir + "/hook-failures.jsonl`"
	if !strings.Contains(page, claim) {
		t.Fatalf("fail-modes.mdx must scope the sandbox log claim to shell hooks: %q", claim)
	}
	if strings.Contains(page, "Sandbox hooks write the same record") {
		t.Fatal("fail-modes.mdx promises a failure record from every sandbox hook")
	}
	const tail = " sandbox plugins block those calls too but write no record."
	if len(silent) == 0 {
		if strings.Contains(page, tail) {
			t.Fatal("fail-modes.mdx names sandbox plugins that write no record, but every sandbox hook logs")
		}
		return
	}
	names := strings.Join(silent, ", ")
	if len(silent) > 1 {
		names = strings.Join(silent[:len(silent)-1], ", ") + " and " + silent[len(silent)-1]
	}
	if want := "The " + names + tail; !strings.Contains(page, want) {
		t.Fatalf("fail-modes.mdx must name the sandbox plugins that write no failure record: %q", want)
	}
}
