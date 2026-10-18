// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-0112: Claude Code started a project's server and called its tool
// before the discovery poll had admitted it, so a decoy that a scan rejects
// answered the call. A call of a watched server without an admission
// outcome is pending: refused, and its admission runs at once. Once the
// rejected verdict is recorded the runtime disable refuses it instead.
func TestMCPServerWithoutAdmissionIsPendingUntilAdmitted(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	project := filepath.Join(t.TempDir(), "decoy-proj")
	server := config.MCPServerEntry{Name: "gb05-decoy", Command: "npx", Args: []string{"-y", "."},
		Connector: "claudecode", Project: project, SourceScope: "project"}
	var admitted []AdmissionResult
	w := New(cfg, nil, nil, store, logger, nil, func(r AdmissionResult) { admitted = append(admitted, r) })
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &countingScanner{name: "mcp-scanner", findings: []scanner.Finding{{
			ID: "f1", RuleID: "MCP-001", Severity: scanner.SeverityHigh, Title: "credential harvesting",
		}}}
	}
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
	w.firstCycleDone.Store(true)

	query := MCPAdmissionQuery{Connector: "claudecode", Server: "gb05-decoy", CWD: filepath.Join(project, "src")}
	if name, pending := w.MCPAdmissionPending(query); !pending || name != "gb05-decoy" {
		t.Fatalf("MCPAdmissionPending = %q, %v; want gb05-decoy pending", name, pending)
	}
	// The pending call queued the admission; the added-server loop runs it.
	w.admitAddedMCPServers(context.Background())
	if len(admitted) != 1 || admitted[0].Verdict != VerdictRejected {
		t.Fatalf("admitted %+v, want gb05-decoy rejected", admitted)
	}
	if _, pending := w.MCPAdmissionPending(query); pending {
		t.Fatal("a server with an admission outcome is still pending")
	}
	entry, err := store.GetActionForConnector("mcp", "gb05-decoy", "claudecode")
	if err != nil || entry == nil || entry.Actions.Runtime != "disable" {
		t.Fatalf("journal %+v (err %v), want the rejected server disabled at runtime", entry, err)
	}
}

func TestMCPAdmissionPendingKeepsOtherCallsAsBefore(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	project := filepath.Join(t.TempDir(), "proj")
	servers := []config.MCPServerEntry{
		{Name: "notes", Command: "npx", Args: []string{"notes"}, Connector: "claudecode", Project: project, SourceScope: "project"},
		{Name: "time", Command: "uvx", Args: []string{"mcp-server-time"}, Connector: "codex", Home: "/home/u1"},
		{Name: "bundled", Command: "npx", Args: []string{"b"}, Connector: "claudecode", Bundled: true},
	}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })

	// Before the watcher listed the servers present at start, nothing is
	// known to be new.
	if _, pending := w.MCPAdmissionPending(MCPAdmissionQuery{Connector: "claudecode", Server: "notes"}); pending {
		t.Fatal("pending before the startup listing")
	}
	// A server the first cycle lists at start stays with that cycle.
	w.recordStartupMCP([]InstallEvent{{Type: InstallMCP, Name: "notes", Path: MCPEventPath(servers[0])}})
	if _, pending := w.MCPAdmissionPending(MCPAdmissionQuery{Connector: "claudecode", Server: "notes"}); pending {
		t.Fatal("a server listed at start is pending during the first cycle")
	}
	w.firstCycleDone.Store(true)
	for _, tc := range []struct {
		name  string
		query MCPAdmissionQuery
	}{
		{"another project", MCPAdmissionQuery{Connector: "claudecode", Server: "notes", CWD: filepath.Join(t.TempDir(), "other")}},
		{"another connector", MCPAdmissionQuery{Connector: "codex", Server: "notes"}},
		{"another account", MCPAdmissionQuery{Connector: "codex", Server: "time", Home: "/home/u2"}},
		{"a bundled server", MCPAdmissionQuery{Connector: "claudecode", Server: "bundled"}},
		{"an unknown server", MCPAdmissionQuery{Connector: "claudecode", Server: "nowhere"}},
	} {
		if _, pending := w.MCPAdmissionPending(tc.query); pending {
			t.Errorf("%s: pending", tc.name)
		}
	}
	if _, pending := w.MCPAdmissionPending(MCPAdmissionQuery{Connector: "codex", Server: "time", Home: "/home/u1"}); !pending {
		t.Fatal("the caller's own unadmitted server is not pending")
	}
	cfg.Gateway.Watcher.MCP.TakeAction = false
	if _, pending := w.MCPAdmissionPending(MCPAdmissionQuery{Connector: "codex", Server: "time", Home: "/home/u1"}); pending {
		t.Fatal("pending although the watcher does not enforce MCP admission")
	}
}

// GAP-0134: an MCP server whose scan failed left an asset_not_scanned issue
// that nothing removed after its project and configuration were deleted, so
// status and verify kept warning about it. Discovery forgets the issues of
// servers no longer configured.
func TestRemovedMCPServerLeavesNoAdmissionIssue(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	servers := []config.MCPServerEntry{{Name: "gone", Command: "npx", Args: []string{"-y", "."},
		Connector: "claudecode", Project: filepath.Join(t.TempDir(), "proj"), SourceScope: "project"}}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &failingScanner{countingScanner{name: "mcp-scanner"}} }
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })
	w.SetMCPDiscoveryPoll(true)
	w.firstCycleDone.Store(true)
	w.AdmitAddedMCPServers([]string{"gone"})
	w.admitAddedMCPServers(context.Background())
	if issues, _ := ReadAdmissionIssues(cfg.DataDir); len(issues) != 1 || issues[0].Kind != AdmissionUnscanned {
		t.Fatalf("issues after the failed scan: %+v", issues)
	}
	w.discoverAddedMCPServers()
	if issues, _ := ReadAdmissionIssues(cfg.DataDir); len(issues) != 1 {
		t.Fatalf("a configured server lost its issue: %+v", issues)
	}
	servers = nil
	w.discoverAddedMCPServers()
	if issues, _ := ReadAdmissionIssues(cfg.DataDir); len(issues) != 0 {
		t.Fatalf("issues after the server was removed: %+v", issues)
	}
}
