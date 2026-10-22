// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The Codex page's managed section quotes the Windows hook program and
// requirements file lines as enterprise policy verify prints them.
func TestCodexPageQuotesTheVerifyLines(t *testing.T) {
	resetEnterprisePolicyFlags(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "content", "docs", "connectors", "codex.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(raw), "## On a managed computer")
	if !ok {
		t.Fatal("codex.mdx has no managed section")
	}
	section, _, _ = strings.Cut(section, "\n## ")
	blocks := []string{}
	for _, m := range regexp.MustCompile("(?s)```text\n(.*?)```").FindAllStringSubmatch(section, -1) {
		blocks = append(blocks, m[1])
	}

	layout, err := managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	opts := enterprisepolicy.LayoutOptions(layout, `C:\Program Files`, `C:\ProgramData`)
	requirements, err := enterprisepolicy.CodexRequirementsPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	// The report marks a file this host cannot see; render with one it can
	// and put the Windows path back.
	present := filepath.Join(t.TempDir(), "requirements.toml")
	if err := os.WriteFile(present, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	report := enterprisePolicyReport{goos: "windows", HookBinary: opts.HookBinary, Result: enterprisepolicy.Result{States: []enterprisepolicy.State{
		{Connector: "codex", Route: enterprisepolicy.RouteMachinePolicy, Covered: true, Paths: []string{present}},
	}}}
	var out bytes.Buffer
	if err := writeEnterprisePolicyReport(&out, report); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.ReplaceAll(out.String(), present, requirements), "\n")
	header, file := lines[0], ""
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "file:") {
			file = line
		}
	}
	if !strings.HasPrefix(header, "Standalone machine agent policy (hook binary ") || file == "" {
		t.Fatalf("unexpected verify output:\n%s", out.String())
	}
	for _, line := range []string{header, file} {
		if !slices.Contains(blocks, line+"\n") {
			t.Errorf("the managed section does not quote the verify line %q", line)
		}
	}
}
