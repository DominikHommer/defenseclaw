// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// listedAgentIdentityRows reads GET /api/v1/agents/identities as an
// administrator view prints it: the raw JSON object of each row.
func listedAgentIdentityRows(t *testing.T) map[string]map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	(&APIServer{}).handleAgentIdentities(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agents/identities", nil))
	var body struct {
		Identities []map[string]any `json:"identities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("identities response %d %s", rec.Code, rec.Body.String())
	}
	rows := map[string]map[string]any{}
	for _, row := range body.Identities {
		id, _ := row["agent_id"].(string)
		rows[id] = row
	}
	return rows
}

// rel-1-0-4 GAP-0596: agent-identities names the sub-agents an agent ran,
// on every OS: a sub-agent that shares its parent's session (a Claude Code
// Task) and one in a child session (a Codex thread) are each counted once,
// also when they hook again after a gateway restart, and the row names the
// newest one's instance (ais-), the id the audit records of that sub-agent
// carry.
func TestAgentIdentitiesListTheSubagentsOfEachAgent(t *testing.T) {
	agentIdentityTestSetup(t)
	store, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	prev := sharedAgentIdentities
	t.Cleanup(func() { sharedAgentIdentities = prev })
	restart := func() {
		sharedAgentIdentities = &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
		sharedAgentIdentities.setStoreSource(func() *inventory.InventoryStore { return store }, nil, nil)
		InstallSharedAgentRegistry("", "")
	}
	restart()
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 4949, Name: "frank", Home: t.TempDir()})
	main := agentHookRequest{ConnectorName: "claudecode", SessionID: "sess-main", HookEventName: "PreToolUse", Payload: map[string]interface{}{}}
	task := main
	task.AgentID = "task-1"
	task.Payload = map[string]interface{}{"agent_id": "task-1"}
	child := main
	child.SessionID = "sess-child"

	parent := agentIdentityForGenericHook(peer, main)
	inSession := agentIdentityForGenericHook(peer, task).AgentInstanceID
	if parent.IdentityID == "" || inSession != agentidentity.SubagentInstanceID(parent.AgentInstanceID, "task-1") {
		t.Fatalf("hooks gave identity %q and sub-agent instance %q", parent.IdentityID, inSession)
	}
	// The child session hooks before and after its link to the parent is
	// learned; it is one sub-agent, with the instance its hooks carry.
	time.Sleep(20 * time.Millisecond) // the child session is the newest sub-agent
	agentIdentityForGenericHook(peer, child)
	sharedAgentIdentities.markSubagentSession(parent.IdentityID, child.SessionID)
	childInstance := agentIdentityForGenericHook(peer, child).AgentInstanceID
	if childInstance != agentidentity.InstanceID(parent.IdentityID, child.SessionID) {
		t.Fatalf("child session instance = %q", childInstance)
	}
	// A sub-agent link to a session that never hooks again names no
	// instance the records carry, so it adds none.
	sharedAgentIdentities.markSubagentSession(parent.IdentityID, "sess-never-hooks")

	check := func(when string) {
		t.Helper()
		row := listedAgentIdentityRows(t)[parent.IdentityID]
		if row == nil {
			t.Fatalf("%s: identity %s not listed", when, parent.IdentityID)
		}
		if row["subagents_seen"] != float64(2) || row["last_subagent_id"] != childInstance || row["sessions_seen"] != float64(1) {
			t.Fatalf("%s: row = %v; want subagents_seen 2, last_subagent_id %s and the one chat", when, row, childInstance)
		}
	}
	check("first listing")
	restart()
	agentIdentityForGenericHook(peer, main)
	agentIdentityForGenericHook(peer, task)
	sharedAgentIdentities.markSubagentSession(parent.IdentityID, child.SessionID)
	agentIdentityForGenericHook(peer, child)
	check("after a restart")
}
