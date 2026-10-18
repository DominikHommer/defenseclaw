// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// definitionChangeHarness admits MCP servers whose scan rejects a definition
// whose arguments name a decoy and passes every other one.
type definitionChangeHarness struct {
	t        *testing.T
	w        *InstallWatcher
	store    *audit.Store
	servers  []config.MCPServerEntry
	admitted []AdmissionResult
}

func newDefinitionChangeHarness(t *testing.T, servers ...config.MCPServerEntry) *definitionChangeHarness {
	t.Helper()
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	h := &definitionChangeHarness{t: t, store: store, servers: servers}
	h.w = New(cfg, nil, nil, store, logger, nil, func(r AdmissionResult) { h.admitted = append(h.admitted, r) })
	h.w.scannerFactory = func(evt InstallEvent) scanner.Scanner {
		for _, server := range h.servers {
			if MCPEventPath(server) == evt.Path && strings.Contains(strings.Join(server.Args, " "), "decoy") {
				return &countingScanner{name: "mcp-scanner", findings: []scanner.Finding{{
					ID: "f1", RuleID: "MCP-001", Severity: scanner.SeverityHigh, Title: "credential harvesting",
				}}}
			}
		}
		return &countingScanner{name: "mcp-scanner"}
	}
	h.w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		return append([]config.MCPServerEntry(nil), h.servers...), nil
	})
	h.w.SetMCPDiscoveryPoll(true)
	h.w.firstCycleDone.Store(true)
	return h
}

// poll is one discovery poll and the admissions it queued.
func (h *definitionChangeHarness) poll() []AdmissionResult {
	h.t.Helper()
	before := len(h.admitted)
	h.w.discoverAddedMCPServers()
	h.w.admitAddedMCPServers(context.Background())
	return h.admitted[before:]
}

func (h *definitionChangeHarness) pending(server config.MCPServerEntry) bool {
	_, pending := h.w.MCPAdmissionPending(MCPAdmissionQuery{
		Connector: server.Connector, Server: server.Name, Home: server.Home, CWD: server.Project,
	})
	return pending
}

func (h *definitionChangeHarness) journal(server config.MCPServerEntry) audit.ActionState {
	h.t.Helper()
	entry, err := h.store.GetActionForConnector("mcp", MCPJournalName(server), "claudecode")
	if err != nil {
		h.t.Fatal(err)
	}
	if entry == nil {
		return audit.ActionState{}
	}
	return entry.Actions
}

// GAP-0216: an admitted server changed to a decoy under the same name was
// seen only by the rescan cycle, minutes later, while its calls were allowed
// on the old verdict. The discovery poll (and, on a managed gateway, every
// change of the enrolled users' published servers) now admits a changed
// definition at once: refused until its own scan, then rejected HIGH, and
// its new baseline is kept, so the next poll does not admit it again.
func TestChangedMCPServerIsAdmittedByTheWatchNotTheRescanCycle(t *testing.T) {
	base := t.TempDir()
	h := newDefinitionChangeHarness(t, enrolledMCPServer(base, "1001", "."), enrolledMCPServer(base, "1002", "."))
	if got := h.poll(); len(got) != 2 {
		t.Fatalf("first poll admitted %+v, want both accounts' servers", got)
	}

	h.servers[0].Args = []string{"-y", ".", "--config", "decoy.json"}
	if !h.pending(h.servers[0]) {
		t.Fatal("a changed server kept the clean verdict of its old definition")
	}
	got := h.poll()
	if len(got) != 1 || got[0].Event.Path != MCPEventPath(h.servers[0]) || got[0].Verdict != VerdictRejected || got[0].MaxSeverity != "HIGH" {
		t.Fatalf("poll after the change admitted %+v, want only the changed server, rejected HIGH", got)
	}
	if h.pending(h.servers[0]) {
		t.Fatal("still pending after its admission: the new baseline was not kept")
	}
	if state := h.journal(h.servers[0]); state.Runtime != "disable" || state.Install != "block" {
		t.Fatalf("journal of the changed server %+v, want blocked and disabled", state)
	}
	if state := h.journal(h.servers[1]); !state.IsEmpty() {
		t.Fatalf("the other account's same-name server got %+v", state)
	}
	if got := h.poll(); len(got) != 0 {
		t.Fatalf("an unchanged server was admitted again: %+v", got)
	}
}

// GAP-0266: a server changed to a decoy, rejected, and then restored to its
// benign definition was admitted clean but stayed refused with the decoy's
// reason. The clean admission of the changed definition lifts the watcher's
// own rejection; the other account's server and an operator block stay as
// they are.
func TestRestoredMCPServerIsReleasedByItsCleanAdmission(t *testing.T) {
	base := t.TempDir()
	h := newDefinitionChangeHarness(t, enrolledMCPServer(base, "1001", "."), enrolledMCPServer(base, "1002", "decoy"))
	h.poll()
	if state := h.journal(h.servers[1]); state.Runtime != "disable" {
		t.Fatalf("the second account's decoy is not disabled: %+v", state)
	}

	h.servers[0].Args = []string{"-y", "decoy"}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictRejected {
		t.Fatalf("decoy admission %+v, want rejected", got)
	}
	h.servers[0].Args = []string{"-y", "."}
	if !h.pending(h.servers[0]) {
		t.Fatal("the restored definition is not pending before its own scan")
	}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("restore admission %+v, want clean", got)
	}
	if state := h.journal(h.servers[0]); !state.IsEmpty() {
		t.Fatalf("the restored, clean server is still refused: %+v", state)
	}
	if h.pending(h.servers[0]) {
		t.Fatal("the restored server is pending after its clean admission")
	}
	if state := h.journal(h.servers[1]); state.Runtime != "disable" {
		t.Fatalf("the other account's rejected server was released: %+v", state)
	}
	events, err := h.store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	for _, event := range events {
		if event.Action == string(audit.ActionEnable) && event.Target == MCPEventPath(h.servers[0]) &&
			strings.Contains(event.Details, "admission allowed its changed definition") {
			released = true
		}
	}
	if !released {
		t.Fatal("no enable row says why the block was lifted")
	}

	// An operator block of the server is not the watcher's to lift.
	key := MCPJournalName(h.servers[0])
	if err := h.store.SetActionFieldForConnector("mcp", key, "claudecode", "runtime", "disable", "operator: hold"); err != nil {
		t.Fatal(err)
	}
	h.servers[0].Args = []string{"-y", ".", "--quiet"}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("admission after the operator block %+v, want clean", got)
	}
	if state := h.journal(h.servers[0]); state.Runtime != "disable" {
		t.Fatalf("a clean admission lifted an operator block: %+v", state)
	}
}

// A per-user gateway journals a project server under its bare name, so two
// projects' servers of one name share a row. Restoring one of them must not
// free the other's rejection.
func TestRestoredMCPServerKeepsABlockAnotherServerShares(t *testing.T) {
	root := t.TempDir()
	project := func(name, args string) config.MCPServerEntry {
		return config.MCPServerEntry{Name: "notes", Command: "npx", Args: []string{"-y", args},
			Connector: "claudecode", Project: filepath.Join(root, name), SourceScope: "project"}
	}
	h := newDefinitionChangeHarness(t, project("a", "decoy"), project("b", "."))
	h.poll()
	h.servers[1].Args = []string{"-y", "decoy"}
	h.poll()
	h.servers[1].Args = []string{"-y", "."}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("restore admission %+v, want clean", got)
	}
	if state := h.journal(h.servers[0]); state.Runtime != "disable" {
		t.Fatalf("project a's rejected server was freed by project b's restore: %+v", state)
	}
}
