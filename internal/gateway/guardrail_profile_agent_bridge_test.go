// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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
		var out []inventory.AgentIdentityRecord
		for _, rec := range *records {
			if len(filter.AgentIDs) > 0 && !slices.Contains(filter.AgentIDs, rec.AgentID) ||
				filter.User != "" && rec.UserID != filter.User {
				continue
			}
			out = append(out, rec)
		}
		return out, true
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
	if got := set.profileAgent(corp); got != legacy {
		t.Errorf("corp's agent matches as %q, want its legacy identity %q", got, legacy)
	}
	if got := set.profileAgent(lab); got != lab {
		t.Errorf("the lab namesake's agent matches as %q, want its own identity %q", got, lab)
	}
	if *asked != 2 {
		t.Errorf("ledger read %d times, want twice (the entries, then their uid) for both requests", *asked)
	}
	named := &guardrailProfileSet{assignments: []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}}},
		{Profile: "strict", Match: config.ProfileMatch{Agents: []string{corp}}},
	}}
	if got := named.profileAgent(corp); got != corp {
		t.Errorf("an assignment naming the current identity lost to the legacy one: %q", got)
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
	if got := set.profileAgent(lab); got != legacy {
		t.Fatalf("with one account recorded, lab's agent matches as %q, want %q", got, legacy)
	}
	// corp's agent is seen after the upgrade.
	records = append(records, legacyBridgeRecord(corp, "alice@corp.example"))
	if got := set.profileAgent(lab); got != legacy {
		t.Fatalf("the link was read again before its refresh: %q", got)
	}
	set.agentBridge.readAt = time.Time{}
	if got := set.profileAgent(lab); got != lab {
		t.Errorf("lab's agent matches as %q after corp was recorded, want its own identity %q", got, lab)
	}
	if got := set.profileAgent(corp); got != corp {
		t.Errorf("corp's agent matches as %q, want its own identity %q", got, corp)
	}
	// Another machine's, or another uid's, namesake proves nothing here.
	other := legacyBridgeRecord(corp, "alice@corp.example")
	other.MachineHash = agentidentity.MachineHash("fedcba9876543210fedcba9876543210")
	records = []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@lab.example"), other}
	fresh := &guardrailProfileSet{assignments: set.assignments}
	if got := fresh.profileAgent(lab); got != legacy {
		t.Errorf("a namesake on another machine took the link: %q", got)
	}
}
