// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// legacyBridgeLedger serves records as the agent ledger and counts reads.
func legacyBridgeLedger(t *testing.T, records *[]inventory.AgentIdentityRecord) *int {
	t.Helper()
	previous := profileAgentLedger
	t.Cleanup(func() { profileAgentLedger = previous })
	asked := 0
	profileAgentLedger = func(filter inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) {
		asked++
		if !filter.Retired {
			t.Errorf("the bridge read the ledger without the records a prune kept aside: %+v", filter)
		}
		return slices.Clone(*records), true
	}
	return &asked
}

func legacyBridgeInputs(account string) agentidentity.Inputs {
	return agentidentity.Inputs{
		MachineHash: agentidentity.MachineHash("0123456789abcdef0123456789abcdef"), UserID: "70001",
		Connector: "codex", InstallFP: "/home/alice/.codex", Account: account,
	}
}

func legacyBridgeRecord(id, account string) inventory.AgentIdentityRecord {
	in := legacyBridgeInputs(account)
	return inventory.AgentIdentityRecord{
		AgentID: id, UserID: in.UserID, UserName: account, Connector: in.Connector,
		InstallFP: in.InstallFP, MachineHash: in.MachineHash,
	}
}

// legacyBridgeDerives stands in for the hook path's derivation of a
// request's 1.0.3 identity, for the agents of accounts.
func legacyBridgeDerives(t *testing.T, accounts ...agentidentity.Inputs) {
	t.Helper()
	previous := profileAgentLegacySource
	t.Cleanup(func() { profileAgentLegacySource = previous })
	profileAgentLegacySource = func(_ context.Context, agent string) (string, bool) {
		for _, in := range accounts {
			if agentidentity.AgentID(in) == agent {
				return agentidentity.LegacyAgentID(in), true
			}
		}
		return "", false
	}
}

// An assignment written for a 1.0.3 agent identity keeps selecting the
// account that identity was recorded for, under the identity that account
// has now, and not a namesake of another domain given the same uid later
// (GAP-1055).
func TestLegacyAgentAssignmentSelectsOnlyItsRecordedAccount(t *testing.T) {
	legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
	corp, lab := agentidentity.AgentID(legacyBridgeInputs("alice@corp.example")), agentidentity.AgentID(legacyBridgeInputs("alice@lab.example"))
	if legacy == "" || corp == lab || corp == legacy {
		t.Fatalf("legacy %q, corp %q, lab %q: want three identities", legacy, corp, lab)
	}
	records := []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@corp.example")}
	asked := legacyBridgeLedger(t, &records)
	set := &guardrailProfileSet{assignments: []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}}},
	}}
	if got, _ := set.profileAgent(corp, nil); got != profileAgentIDs(corp, legacy) {
		t.Errorf("corp's agent matches as %q, want its identity and its legacy identity %q", got, legacy)
	}
	if got, _ := set.profileAgent(lab, nil); got != lab {
		t.Errorf("the lab namesake's agent matches as %q, want its own identity %q", got, lab)
	}
	if *asked != 1 {
		t.Errorf("ledger read %d times, want once for both requests", *asked)
	}
	named := &guardrailProfileSet{assignments: []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}}},
		{Profile: "strict", Match: config.ProfileMatch{Agents: []string{corp}}},
	}}
	// An assignment naming the current identity does not skip the link:
	// both are matched in assignment order.
	if got, _ := named.profileAgent(corp, nil); got != profileAgentIDs(corp, legacy) {
		t.Errorf("with an assignment naming the current identity, corp's agent matches as %q, want both identities", got)
	}
}

// 1.0.3 wrote a later namesake's name over the legacy record of an earlier
// one of another domain that held the same uid. Once the ledger shows both
// accounts, the legacy assignment selects neither of them, also when it was
// linked before the second account was recorded.
func TestLegacyAgentAssignmentWithAnOverwrittenRecordSelectsNeitherAccount(t *testing.T) {
	legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
	corp, lab := agentidentity.AgentID(legacyBridgeInputs("alice@corp.example")), agentidentity.AgentID(legacyBridgeInputs("alice@lab.example"))
	// The record names lab: its sighting came last before the upgrade.
	records := []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@lab.example")}
	legacyBridgeLedger(t, &records)
	set := &guardrailProfileSet{assignments: []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}}},
	}}
	if got, _ := set.profileAgent(lab, nil); got != profileAgentIDs(lab, legacy) {
		t.Fatalf("with one account recorded, lab's agent matches as %q, want %q too", got, legacy)
	}
	// corp's agent is seen after the upgrade.
	records = append(records, legacyBridgeRecord(corp, "alice@corp.example"))
	if got, _ := set.profileAgent(lab, nil); got != profileAgentIDs(lab, legacy) {
		t.Fatalf("the link was read again before its refresh: %q", got)
	}
	set.agentBridge.readAt = time.Time{}
	if got, _ := set.profileAgent(lab, nil); got != lab {
		t.Errorf("lab's agent matches as %q after corp was recorded, want its own identity %q", got, lab)
	}
	if got, _ := set.profileAgent(corp, nil); got != corp {
		t.Errorf("corp's agent matches as %q, want its own identity %q", got, corp)
	}
	// Another machine's, or another uid's, namesake proves nothing here.
	other := legacyBridgeRecord(corp, "alice@corp.example")
	other.MachineHash = agentidentity.MachineHash("fedcba9876543210fedcba9876543210")
	records = []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@lab.example"), other}
	fresh := &guardrailProfileSet{assignments: set.assignments}
	if got, _ := fresh.profileAgent(lab, nil); got != profileAgentIDs(lab, legacy) {
		t.Errorf("a namesake on another machine took the link: %q", got)
	}
}

// An assignment whose agents entry may be the agent's 1.0.3 identity, while
// the ledger cannot say whose it is, selects the outage default
// (default_lookup_failed) for the hook: a later, weaker assignment does not
// apply in its place. An agent the entry cannot name keeps its own match.
func TestUnresolvedLegacyAgentAssignmentSelectsTheOutageDefault(t *testing.T) {
	stubProfileSources(t)
	legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
	corp, lab := agentidentity.AgentID(legacyBridgeInputs("alice@corp.example")), agentidentity.AgentID(legacyBridgeInputs("alice@lab.example"))
	bob := agentidentity.Inputs{
		MachineHash: agentidentity.MachineHash("0123456789abcdef0123456789abcdef"), UserID: "70002",
		Connector: "codex", InstallFP: "/home/bob/.codex", Account: "bob@corp.example",
	}
	other := agentidentity.AgentID(bob)
	legacyBridgeDerives(t, legacyBridgeInputs("alice@corp.example"), legacyBridgeInputs("alice@lab.example"), bob)
	// 1.0.3 recorded the entry for both namesakes of uid 70001.
	records := []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@lab.example"), legacyBridgeRecord(corp, "alice@corp.example")}
	legacyBridgeLedger(t, &records)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Mode: "action"}, "watch": {Mode: "observe"}}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Agents: []string{legacy}}},
		{Profile: "watch", Match: config.ProfileMatch{Connectors: []string{"codex"}}},
	}
	cfg.Guardrail.DefaultProfile = "strict"
	hook := func(agent string) (profileDecision, string) {
		api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
		profileAgentSource = func(context.Context) (string, bool) { return agent, true }
		ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "70001", UserName: "alice"})
		ctx = api.withGuardrailProfileDecision(ctx, "codex")
		return api.resolveProfile(ctx), api.agentHookMode(ctx, "codex")
	}
	for name, agent := range map[string]string{"corp": corp, "lab": lab} {
		if got, mode := hook(agent); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
			t.Errorf("%s: profile %+v, mode %q; want the outage default strict (action)", name, got, mode)
		}
	}
	if got, mode := hook(other); got.Name != "watch" || got.Match != profileMatchConnector || mode != "observe" {
		t.Errorf("another account's agent: profile %+v, mode %q; want its connector assignment", got, mode)
	}
	// The ledger cannot be read: the entry may be the agent's own legacy
	// identity, and any agent's when the request does not derive that.
	profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) { return nil, false }
	if got, mode := hook(corp); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
		t.Errorf("unreadable ledger, corp: profile %+v, mode %q; want the outage default strict (action)", got, mode)
	}
	if got, mode := hook(other); got.Name != "watch" || got.Match != profileMatchConnector || mode != "observe" {
		t.Errorf("unreadable ledger, another account: profile %+v, mode %q; want its connector assignment", got, mode)
	}
	legacyBridgeDerives(t)
	if got, mode := hook(other); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
		t.Errorf("unreadable ledger, not derived: profile %+v, mode %q; want the outage default strict (action)", got, mode)
	}
	// An assignment naming the agent's current identity needs no ledger.
	cfg.Guardrail.ProfileAssignments = append([]config.ProfileAssignment{
		{Profile: "watch", Match: config.ProfileMatch{Agents: []string{corp}}},
	}, cfg.Guardrail.ProfileAssignments...)
	if got, _ := hook(corp); got.Name != "watch" || got.Match != profileMatchAgent {
		t.Errorf("named identity: profile %+v, want its agent assignment", got)
	}
}

// legacyBridgeHook resolves the profile and hook mode of a request of agent
// by alice (uid 70001) for codex under assignments: the 1.0.3 entry first
// (relaxed), then every codex agent (watch); the default is strict.
func legacyBridgeHook(t *testing.T, legacy string) func(agent string) (profileDecision, string) {
	t.Helper()
	stubProfileSources(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict": {Mode: "action"}, "relaxed": {Mode: "action"}, "watch": {Mode: "observe"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}}},
		{Profile: "watch", Match: config.ProfileMatch{Connectors: []string{"codex"}}},
	}
	cfg.Guardrail.DefaultProfile = "strict"
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	return func(agent string) (profileDecision, string) {
		profileAgentSource = func(context.Context) (string, bool) { return agent, true }
		ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "70001", UserName: "alice"})
		ctx = api.withGuardrailProfileDecision(ctx, "codex")
		return api.resolveProfile(ctx), api.agentHookMode(ctx, "codex")
	}
}

// A 1.0.3 agents entry keeps selecting its account after the ledger's
// retention pruned the record 1.0.3 wrote for it, and stays unresolved for
// namesakes whose records were pruned: a readable ledger without the
// record is no proof that the entry names no one, and a later, weaker
// assignment never applies in its place.
func TestPrunedLegacyAgentAssignmentKeepsItsAccount(t *testing.T) {
	legacy := agentidentity.LegacyAgentID(legacyBridgeInputs("alice@corp.example"))
	corp, lab := agentidentity.AgentID(legacyBridgeInputs("alice@corp.example")), agentidentity.AgentID(legacyBridgeInputs("alice@lab.example"))
	old, now := time.Now().Add(-200*24*time.Hour), time.Now()
	at := func(rec inventory.AgentIdentityRecord, seen time.Time) inventory.AgentIdentityRecord {
		rec.FirstSeen, rec.LastSeen = seen, seen
		return rec
	}
	pruned := func(t *testing.T, records ...inventory.AgentIdentityRecord) {
		t.Helper()
		st, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if err := st.UpsertAgentIdentities(t.Context(), records); err != nil {
			t.Fatal(err)
		}
		if _, err := st.PruneAgentIdentities(t.Context(), now.Add(-90*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
		previous := profileAgentLedger
		t.Cleanup(func() { profileAgentLedger = previous })
		profileAgentLedger = func(filter inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) {
			records, _, err := st.ListAgentIdentities(context.Background(), filter)
			return records, err == nil
		}
	}
	outage := func(t *testing.T, what string, got profileDecision, mode string) {
		t.Helper()
		if got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
			t.Errorf("%s: profile %+v, mode %q; want the outage default strict (action)", what, got, mode)
		}
	}
	t.Run("pruned legacy record", func(t *testing.T) {
		pruned(t, at(legacyBridgeRecord(legacy, "alice@corp.example"), old), at(legacyBridgeRecord(corp, "alice@corp.example"), now))
		hook := legacyBridgeHook(t, legacy)
		if got, _ := hook(corp); got.Name != "relaxed" || got.Match != profileMatchAgent {
			t.Errorf("corp's agent after the prune: profile %+v, want its 1.0.3 assignment relaxed", got)
		}
	})
	t.Run("pruned namesake", func(t *testing.T) {
		pruned(t, at(legacyBridgeRecord(legacy, "alice@lab.example"), old), at(legacyBridgeRecord(corp, "alice@corp.example"), old))
		hook := legacyBridgeHook(t, legacy)
		got, mode := hook(lab)
		outage(t, "lab's agent after the namesake's record was pruned", got, mode)
	})
	t.Run("pruned before the upgrade", func(t *testing.T) {
		// 1.0.3 pruned its own record of the idle agent: only the record
		// 1.0.4 wrote is left.
		pruned(t, at(legacyBridgeRecord(corp, "alice@corp.example"), now))
		hook := legacyBridgeHook(t, legacy)
		got, mode := hook(corp)
		outage(t, "corp's agent without a 1.0.3 record", got, mode)
	})
	t.Run("not recorded yet", func(t *testing.T) {
		pruned(t)
		bobIn := agentidentity.Inputs{
			MachineHash: agentidentity.MachineHash("0123456789abcdef0123456789abcdef"), UserID: "70002",
			Connector: "codex", InstallFP: "/home/bob/.codex", Account: "bob@corp.example",
		}
		legacyBridgeDerives(t, legacyBridgeInputs("alice@corp.example"), bobIn)
		hook := legacyBridgeHook(t, legacy)
		got, mode := hook(corp)
		outage(t, "corp's agent the hook path derived", got, mode)
		bob := agentidentity.AgentID(bobIn)
		if got, mode := hook(bob); got.Name != "watch" || got.Match != profileMatchConnector || mode != "observe" {
			t.Errorf("another account's agent: profile %+v, mode %q; want its connector assignment", got, mode)
		}
	})
}
