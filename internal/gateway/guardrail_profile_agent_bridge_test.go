// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// An assignment written for a 1.0.3 agent identity keeps selecting the
// account that identity was recorded for, under the identity that account
// has now, and not a namesake of another domain given the same uid later
// (GAP-1055).
func TestLegacyAgentAssignmentSelectsOnlyItsRecordedAccount(t *testing.T) {
	machine := agentidentity.MachineHash("0123456789abcdef0123456789abcdef")
	in := func(account string) agentidentity.Inputs {
		return agentidentity.Inputs{MachineHash: machine, UserID: "70001", Connector: "codex", InstallFP: "/home/alice/.codex", Account: account}
	}
	legacy := agentidentity.LegacyAgentID(in("alice@corp.example"))
	corp, lab := agentidentity.AgentID(in("alice@corp.example")), agentidentity.AgentID(in("alice@lab.example"))
	if legacy == "" || corp == lab || corp == legacy {
		t.Fatalf("legacy %q, corp %q, lab %q: want three identities", legacy, corp, lab)
	}
	previous := profileAgentLedger
	t.Cleanup(func() { profileAgentLedger = previous })
	asked := 0
	profileAgentLedger = func(ids []string) ([]inventory.AgentIdentityRecord, bool) {
		asked++
		return []inventory.AgentIdentityRecord{{
			AgentID: legacy, UserID: "70001", UserName: "alice@corp.example", Connector: "codex",
			InstallFP: "/home/alice/.codex", MachineHash: machine,
		}}, true
	}
	set := &guardrailProfileSet{assignments: []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}}},
	}}
	if got := set.profileAgent(corp); got != legacy {
		t.Errorf("corp's agent matches as %q, want its legacy identity %q", got, legacy)
	}
	if got := set.profileAgent(lab); got != lab {
		t.Errorf("the lab namesake's agent matches as %q, want its own identity %q", got, lab)
	}
	if asked != 1 {
		t.Errorf("ledger asked %d times, want once", asked)
	}
	named := &guardrailProfileSet{assignments: []config.ProfileAssignment{
		{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{legacy}}},
		{Profile: "strict", Match: config.ProfileMatch{Agents: []string{corp}}},
	}}
	if got := named.profileAgent(corp); got != corp {
		t.Errorf("an assignment naming the current identity lost to the legacy one: %q", got)
	}
}
