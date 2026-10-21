// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package agentidentity

import (
	"regexp"
	"testing"
)

// Two directory principals of one short name in two domains that hold one
// uid in turn get two agent identities, and the second is a reassignment
// of the first's uid. An unqualified account keeps the ID 1.0.3 gave it,
// and a qualified one names that ID as its legacy ID (GAP-1055).
func TestQualifiedAccountsOfTwoDomainsGetTwoIdentities(t *testing.T) {
	machine := MachineHash("0123456789abcdef0123456789abcdef")
	in := func(account string) Inputs {
		return Inputs{MachineHash: machine, UserID: "70001", Connector: "codex", InstallFP: "/home/alice/.codex", Account: account}
	}
	corp, lab := AgentID(in("alice@corp.example")), AgentID(in("alice@lab.example"))
	if corp == "" || corp == lab {
		t.Fatalf("AgentID corp %q, lab %q; want two identities", corp, lab)
	}
	if AgentID(in("ALICE@Corp.Example")) != corp {
		t.Errorf("the case of a qualified name changed its ID")
	}
	if !UIDReassigned("70001", "alice@corp.example", "alice@lab.example") {
		t.Errorf("a namesake from another domain is not a reassignment of the uid")
	}
	if UIDReassigned("70001", "alice@corp.example", "alice") || UIDReassigned("70001", "alice", "CORP\\alice") {
		t.Errorf("a bare name proves no other domain")
	}
	bare := AgentID(in("alice"))
	if legacy := LegacyAgentID(in("alice@corp.example")); legacy != bare || LegacyAgentID(in("alice@lab.example")) != bare {
		t.Errorf("LegacyAgentID = %q, want the domain-free ID %q", legacy, bare)
	}
	if LegacyAgentID(in("alice")) != "" {
		t.Errorf("a bare account has no legacy ID")
	}
	if got := AgentID(in("alice")); got != "agt-"+digest16(agentNamespace, machine, "70001", "codex", "/home/alice/.codex", "alice") {
		t.Errorf("a bare account's ID changed: %q", got)
	}
}

func TestDerivationTable(t *testing.T) {
	machine := MachineHash("0123456789abcdef0123456789abcdef")
	base := Inputs{MachineHash: machine, UserID: "1001", Connector: "claudecode", InstallFP: "/home/alice/.claude"}
	baseID := AgentID(base)
	if !regexp.MustCompile(`^agt-[0-9a-f]{16}$`).MatchString(baseID) {
		t.Fatalf("AgentID = %q, want agt- plus 16 hex", baseID)
	}
	with := func(edit func(*Inputs)) Inputs { in := base; edit(&in); return in }
	for _, tc := range []struct {
		name string
		in   Inputs
		same bool
	}{
		{"spacing and connector case", with(func(in *Inputs) { in.UserID, in.Connector = " 1001 ", "ClaudeCode" }), true},
		{"trailing separator", with(func(in *Inputs) { in.InstallFP = "/home/alice/.claude/" }), true},
		{"machine id case", with(func(in *Inputs) { in.MachineHash = MachineHash("0123456789ABCDEF0123456789ABCDEF") }), true},
		{"other machine", with(func(in *Inputs) { in.MachineHash = MachineHash("ffff") }), false},
		{"other user", with(func(in *Inputs) { in.UserID = "1002" }), false},
		{"other connector", with(func(in *Inputs) { in.Connector = "codex" }), false},
		{"other install", with(func(in *Inputs) { in.InstallFP = "/home/alice/.claude-work" }), false},
	} {
		if got := AgentID(tc.in); (got == baseID) != tc.same {
			t.Errorf("%s: AgentID = %q, base %q, want same=%v", tc.name, got, baseID, tc.same)
		}
	}
	for _, in := range []Inputs{
		with(func(in *Inputs) { in.MachineHash = "" }),
		with(func(in *Inputs) { in.UserID = "" }),
		with(func(in *Inputs) { in.Connector = "" }),
	} {
		if got := AgentID(in); got != "" {
			t.Errorf("AgentID(%+v) = %q, want empty for a missing component", in, got)
		}
	}
	sid := Inputs{MachineHash: machine, UserID: "s-1-5-21-1-2-3-1001", Connector: "codex", InstallFP: `C:\Users\Alice\.codex\`}
	sidUpper := Inputs{MachineHash: machine, UserID: "S-1-5-21-1-2-3-1001", Connector: "codex", InstallFP: `c:/users/alice/.codex`}
	if AgentID(sid) != AgentID(sidUpper) {
		t.Errorf("Windows SID and path spellings derived different IDs")
	}

	a, b := InstanceID(baseID, "session-1"), InstanceID(baseID, "session-2")
	if !regexp.MustCompile(`^ais-[0-9a-f]{16}$`).MatchString(a) || a == b {
		t.Fatalf("InstanceID: %q, %q; want distinct ais- ids", a, b)
	}
	if a != InstanceID(baseID, "session-1") || a == InstanceID(AgentID(with(func(in *Inputs) { in.UserID = "1002" })), "session-1") {
		t.Errorf("InstanceID is not keyed by (agent, session)")
	}
	if InstanceID(baseID, "") != "" {
		t.Errorf("InstanceID without a session must be empty")
	}
	sub := SubagentInstanceID(a, "agent-7")
	if sub == "" || sub == a || sub != SubagentInstanceID(a, "agent-7") || sub == SubagentInstanceID(b, "agent-7") {
		t.Errorf("SubagentInstanceID = %q; want stable, distinct from its parent and keyed by parent", sub)
	}
}
