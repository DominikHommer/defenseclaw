// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// rel-1-0-4 GAP-0596: an agent identity row names the account's UPN and
// counts the sub-agent instances the agent ran, each once, on every OS. A
// 1.0.3 (v8) inventory.db is upgraded in place: its rows stay, with no UPN
// and no sub-agents until the agent is seen again.
func TestAgentIdentitiesRecordUPNAndSubagentsAcrossTheV9Upgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.db")
	st, err := NewInventoryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Make the store a v8 one, as 1.0.3 left it, holding one identity.
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS agent_identity_subagents`,
		`ALTER TABLE agent_identities DROP COLUMN user_upn`,
		`ALTER TABLE agent_identities DROP COLUMN subagents_seen`,
		`ALTER TABLE agent_identities DROP COLUMN last_subagent_id`,
		`DELETE FROM schema_version WHERE version = 9`,
		`INSERT INTO agent_identities (agent_id, user_id, user_name, connector, install_fp, machine_hash, first_seen, last_seen, last_session_id, sessions_seen)
			VALUES ('agt-00000000000000c1', 'S-1-5-21-1-2-3-1104', 'carol', 'codex', '', 'm', '2026-10-01T00:00:00.000000000Z', '2026-10-01T00:00:00.000000000Z', 's0', 4)`,
	} {
		if _, err := st.db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	_ = st.Close()
	if st, err = NewInventoryStore(path); err != nil {
		t.Fatalf("upgrade the v8 store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if v, _ := st.SchemaVersion(); v != len(inventoryMigrations) {
		t.Fatalf("schema version after the upgrade = %d, want %d", v, len(inventoryMigrations))
	}
	rows, _, err := st.ListAgentIdentities(ctx, AgentIdentityFilter{})
	if err != nil || len(rows) != 1 || rows[0].SessionsSeen != 4 || rows[0].UPN != "" || rows[0].SubagentsSeen != 0 {
		t.Fatalf("1.0.3 row after the upgrade = %+v, err %v", rows, err)
	}

	t0 := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	carol := AgentIdentityRecord{
		AgentID: "agt-00000000000000c1", UserID: "S-1-5-21-1-2-3-1104", UserName: "carol", UPN: "carol@corp.example.com",
		Connector: "codex", MachineHash: "m", FirstSeen: t0, LastSeen: t0, LastSessionID: "s1", SessionsSeen: 1, SessionIDs: []string{"s1"},
	}
	subagents := []AgentIdentitySubagent{
		{AgentID: carol.AgentID, InstanceID: "ais-00000000000000b2", Seen: t0.Add(2 * time.Second)},
		{AgentID: carol.AgentID, InstanceID: "ais-00000000000000a1", Seen: t0.Add(time.Second)},
		// An identity the store has no row for gets none.
		{AgentID: "agt-0000000000000099", InstanceID: "ais-0000000000000099", Seen: t0},
	}
	if err := st.UpsertAgentIdentityBatch(ctx, []AgentIdentityRecord{carol}, nil, subagents); err != nil {
		t.Fatal(err)
	}
	// After a gateway restart the same sub-agent hooks again: counted once.
	// A sighting without a UPN keeps the one recorded.
	again := carol
	again.UPN, again.SessionIDs, again.SessionsSeen, again.LastSeen = "", nil, 0, t0.Add(time.Hour)
	if err := st.UpsertAgentIdentityBatch(ctx, []AgentIdentityRecord{again}, nil,
		[]AgentIdentitySubagent{{AgentID: carol.AgentID, InstanceID: "ais-00000000000000a1", Seen: t0.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	rows, _, err = st.ListAgentIdentities(ctx, AgentIdentityFilter{})
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %+v, err %v", rows, err)
	}
	got := rows[0]
	if got.UPN != "carol@corp.example.com" || got.SubagentsSeen != 2 || got.LastSubagentID != "ais-00000000000000b2" || got.SessionsSeen != 5 {
		t.Fatalf("row = %+v; want the UPN, two sub-agents (last ais-00000000000000b2) and five sessions", got)
	}
	var orphans int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_identity_subagents WHERE agent_id = 'agt-0000000000000099'`).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("sub-agent rows of an unknown identity = %d, err %v", orphans, err)
	}

	// The retention sweep expires the sub-agent deduplication rows with the
	// session ones; the count stays cumulative.
	if _, err := st.PruneAgentIdentitySessions(ctx, t0.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var kept []string
	list, err := st.db.QueryContext(ctx, `SELECT instance_id FROM agent_identity_subagents`)
	if err != nil {
		t.Fatal(err)
	}
	for list.Next() {
		var id string
		if err := list.Scan(&id); err != nil {
			t.Fatal(err)
		}
		kept = append(kept, id)
	}
	_ = list.Close()
	if len(kept) != 1 || kept[0] != "ais-00000000000000a1" {
		t.Fatalf("sub-agent rows after the prune = %v, want only the one seen again", kept)
	}
	if rows, _, err = st.ListAgentIdentities(ctx, AgentIdentityFilter{}); err != nil || rows[0].SubagentsSeen != 2 {
		t.Fatalf("count after the prune = %+v, err %v; want 2", rows, err)
	}
}
