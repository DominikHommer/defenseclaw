// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
)

// #1164: the enumerator starts a published server as its user only through
// the launchers a scan starts anywhere else, and never a code-running flag
// or a command cmd.exe could reinterpret.
func TestCheckMCPAsUserDefinitionAppliesTheScanLauncherRules(t *testing.T) {
	ok := map[string]config.MCPServerEntry{
		"npx":     {Name: "a", Command: "npx", Args: []string{"-y", ".", "--config", `.\srv.json`}},
		"npx.cmd": {Name: "a", Command: "NPX.cmd", Args: []string{"@scope/pkg"}},
		"uvx":     {Name: "a", Command: "uvx", Args: []string{"mcp-server-time"}},
	}
	for name, entry := range ok {
		if _, err := checkMCPAsUserDefinition(entry); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
	}
	refused := map[string]config.MCPServerEntry{
		"url":         {Name: "a", URL: "https://example.test/mcp"},
		"path":        {Name: "a", Command: `C:\Users\u\npx.cmd`, Args: []string{"pkg"}},
		"other":       {Name: "a", Command: "node", Args: []string{"server.js"}},
		"shell":       {Name: "a", Command: "cmd.exe", Args: []string{"/c", "x"}},
		"no package":  {Name: "a", Command: "npx", Args: []string{"-y"}},
		"eval flag":   {Name: "a", Command: "npx", Args: []string{"-c", "calc", "pkg"}},
		"exec= flag":  {Name: "a", Command: "uvx", Args: []string{"--exec=x", "pkg"}},
		"metachar":    {Name: "a", Command: "npx", Args: []string{"pkg&calc"}},
		"percent var": {Name: "a", Command: "npx", Args: []string{"%COMSPEC%"}},
	}
	for name, entry := range refused {
		if _, err := checkMCPAsUserDefinition(entry); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// #1164: the request names a published server and pins its definition; a
// server the user changed after the gateway read it, or one of another
// project, is not started.
func TestFindMCPAsUserServerNeedsTheScannedDefinition(t *testing.T) {
	project := `C:\Users\dcw-std1\proj`
	server := config.MCPServerEntry{Name: "notes", Command: "npx", Args: []string{"-y", "."}, Connector: "claudecode", Project: project}
	other := server
	other.Project = `C:\Users\dcw-std1\other`
	other.Args = []string{"-y", "other"}
	request, err := mcpasuser.NewRequest("DefenseClawGateway", "S-1-5-21-1-2-3-1001", server)
	if err != nil {
		t.Fatal(err)
	}
	found, err := findMCPAsUserServer([]config.MCPServerEntry{other, server}, request)
	if err != nil || found.Project != project {
		t.Fatalf("found %+v, %v", found, err)
	}
	upper := request
	upper.Project = strings.ToUpper(project)
	if _, err := findMCPAsUserServer([]config.MCPServerEntry{server}, upper); err != nil {
		t.Fatalf("project case: %v", err)
	}
	changed := server
	changed.Args = []string{"-y", "evil"}
	if _, err := findMCPAsUserServer([]config.MCPServerEntry{changed}, request); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed definition: %v", err)
	}
	if _, err := findMCPAsUserServer([]config.MCPServerEntry{other}, request); err == nil || !strings.Contains(err.Error(), "not in the MCP servers") {
		t.Fatalf("unpublished server: %v", err)
	}
}

func TestMCPAsUserLauncherAndArgv(t *testing.T) {
	files := map[string]bool{`C:\Program Files\nodejs\npx.cmd`: true, `C:\Users\u\AppData\Roaming\npm\npx.cmd`: true}
	isFile := func(path string) bool { return files[path] }
	path := `relative;"C:\Users\u\AppData\Roaming\npm";C:\Program Files\nodejs\`
	if got, err := findMCPLauncherOnPath("npx.cmd", path, isFile); err != nil || got != `C:\Users\u\AppData\Roaming\npm\npx.cmd` {
		t.Fatalf("npx: %q, %v", got, err)
	}
	if _, err := findMCPLauncherOnPath("uvx.exe", path, isFile); err == nil {
		t.Fatal("found a launcher that is not there")
	}
	argv, err := mcpAsUserArgv(mcpAsUserLauncher{name: "npx", file: "npx.cmd"}, `C:\Program Files\nodejs\npx.cmd`, `C:\Windows\System32\cmd.exe`, []string{"-y", "pkg"})
	want := []string{`C:\Windows\System32\cmd.exe`, "/d", "/s", "/v:off", "/c", "call", `C:\Program Files\nodejs\npx.cmd`, "-y", "pkg"}
	if err != nil || strings.Join(argv, "|") != strings.Join(want, "|") {
		t.Fatalf("npx argv %q, %v", argv, err)
	}
	if _, err := mcpAsUserArgv(mcpAsUserLauncher{name: "npx"}, `C:\a&b\npx.cmd`, `C:\Windows\System32\cmd.exe`, nil); err == nil {
		t.Fatal("an npx.cmd path with a metacharacter was accepted")
	}
	argv, err = mcpAsUserArgv(mcpAsUserLauncher{name: "uvx"}, `C:\u\uvx.exe`, "unused", []string{"pkg"})
	if err != nil || strings.Join(argv, "|") != `C:\u\uvx.exe|pkg` {
		t.Fatalf("uvx argv %q, %v", argv, err)
	}
}

func TestMergeMCPAsUserEnvPutsTheServerEnvOnTop(t *testing.T) {
	user := []string{"=C:=C:\\Users\\u", "Path=C:\\Windows", "USERPROFILE=C:\\Users\\u"}
	got := mergeMCPAsUserEnv(user, map[string]string{"PATH": `C:\tools`, "NOTES_TOKEN": "x", "bad=name": "y"})
	want := []string{"=C:=C:\\Users\\u", `PATH=C:\tools`, "USERPROFILE=C:\\Users\\u", "NOTES_TOKEN=x"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("env %q", got)
	}
	if mcpAsUserEnvValue(got, "path") != `C:\tools` {
		t.Fatal("PATH lookup is case sensitive")
	}
}
