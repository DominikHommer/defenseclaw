// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// MCPAdmissionQuery names the MCP server a tool call reaches.
type MCPAdmissionQuery struct {
	// Connector is the hook's connector, Server the server name as the
	// tool call spells it (mcp__<server>__<tool>).
	Connector, Server string
	// Home is the caller's home on a gateway that serves several
	// accounts, "" on a per-user gateway. CWD is the agent's working
	// folder, "" when the hook did not send one.
	Home, CWD string
}

// MCPAdmissionPending reports an MCP server the watcher admits that has no
// admission outcome yet, and queues its admission now (GAP-0112). Claude
// Code starts the servers of a project it opens at once, and the discovery
// poll finds a new project server up to its interval later, so a tool call
// in between reached a server nothing had scanned and was allowed, even one
// a later scan rejected. The hook refuses such a call until admission has
// run: the call fails closed and a retry once the verdict allows it goes
// through. It returns the configured name of the server.
//
// A server the first rescan cycle lists at start stays with that cycle,
// which admits or baselines it (an upgrade from 0.8.x only baselines), so
// the calls of a server configured before the start are decided as before.
// Nothing is pending where the watcher does not enforce MCP admission
// (take_action off), where it has no MCP source, before it has listed the
// servers present at start, or on Secure Client (issue #1092).
func (w *InstallWatcher) MCPAdmissionPending(q MCPAdmissionQuery) (string, bool) {
	if w == nil || !w.admitNewMCP || w.store == nil || w.secureClientActive() ||
		!w.takeActionFor(InstallEvent{Type: InstallMCP}) || strings.TrimSpace(q.Server) == "" {
		return "", false
	}
	firstCycle := !w.firstCycleDone.Load()
	if firstCycle && !w.mcpStartupListed.Load() {
		return "", false
	}
	servers, err := w.readMCPServers()
	if err != nil {
		return "", false
	}
	var pending []string
	for _, server := range servers {
		if server.Bundled || !mcpServerServesQuery(server, q) {
			continue
		}
		path := MCPEventPath(server)
		if firstCycle && w.listedAtStartup(path) {
			continue
		}
		if _, err := w.store.GetTargetSnapshot(string(InstallMCP), path); err == nil {
			continue
		}
		// No outcome yet, or one that could not be read: refused either
		// way, and admission says why when it runs.
		pending = append(pending, server.Name)
	}
	if len(pending) == 0 {
		return "", false
	}
	w.AdmitAddedMCPServers(pending)
	return pending[0], true
}

// mcpServerServesQuery reports whether a watched server can be the one the
// tool call reaches: same connector and name, the caller's own server on a
// gateway of several accounts, and a project server only for an agent
// working in that project.
func mcpServerServesQuery(server config.MCPServerEntry, q MCPAdmissionQuery) bool {
	if c := strings.TrimSpace(server.Connector); c != "" && !strings.EqualFold(c, strings.TrimSpace(q.Connector)) {
		return false
	}
	if !config.SameMCPToolServer(q.Connector, server.Name, q.Server) {
		return false
	}
	if q.Home != "" && server.Home != "" && !sameMCPFolder(server.Home, q.Home) {
		return false
	}
	if q.CWD != "" && server.Project != "" && !mcpFolderWithin(q.CWD, server.Project) {
		return false
	}
	return true
}

func mcpFolderKey(dir string) string {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if runtime.GOOS == "windows" {
		return strings.ToLower(dir)
	}
	return dir
}

func sameMCPFolder(a, b string) bool { return mcpFolderKey(a) == mcpFolderKey(b) }

// mcpFolderWithin reports whether dir is root or a folder inside it.
func mcpFolderWithin(dir, root string) bool {
	rel, err := filepath.Rel(mcpFolderKey(root), mcpFolderKey(dir))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
