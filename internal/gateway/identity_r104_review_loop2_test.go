// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// stubLegacyProof makes every uid's agentIdentityLegacyProof name and
// bound: the name a build before 1.0.4 gave it and whether the account the
// upgrade bound its 1.0.3 identities to holds it, deriving its current
// identities without an incarnation.
func stubLegacyProof(t *testing.T, name string, bound bool) {
	t.Helper()
	previous := agentIdentityLegacyProof
	t.Cleanup(func() { agentIdentityLegacyProof = previous })
	agentIdentityLegacyProof = func(string) (string, string, bool) { return name, "", bound }
}

// loop2Only assigns profile to the agents entry entry only; the default is
// defaultProfile.
func loop2Only(entry, profile, defaultProfile string, profiles map[string]config.GuardrailProfile) *config.Config {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = profiles
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: profile, Match: config.ProfileMatch{Agents: []string{entry}}}}
	cfg.Guardrail.DefaultProfile = defaultProfile
	return cfg
}

// loop2Incomparable are two profiles neither of which enforces all the
// other does: relaxed confines sandboxes, strict blocks from a lower level.
var loop2Incomparable = map[string]config.GuardrailProfile{
	"relaxed": {Mode: "action", BlockAt: "high", Sandbox: &config.OpenShellAdminConfig{EgressAllowOnly: []string{"pkg.example"}}},
	"strict":  {Mode: "action", BlockAt: "low"},
}

// loop2Kept checks that the 1.0.3 entry's relaxed profile applied as the
// agent's own assignment, as 1.0.3 applied it.
func loop2Kept(t *testing.T, what string, got profileDecision, mode string) {
	t.Helper()
	if got.Name != "relaxed" || got.Match != profileMatchAgent || got.Refused != "" || mode != "action" {
		t.Errorf("%s: profile %+v, mode %q; want the 1.0.3 entry's relaxed (action) as agent, not refused", what, got, mode)
	}
}

// loop2Unproven checks that an unproven entry whose profile and the
// default do not cover each other refused the request.
func loop2Unproven(t *testing.T, what string, got profileDecision) {
	t.Helper()
	if got.Refused == "" || got.Match != profileMatchDefaultLookupFailed {
		t.Errorf("%s: profile %+v; want a refusal as default_lookup_failed, never one of the two profiles", what, got)
	}
}

// Review loop 2, finding 1. The current identity of an account other than
// the first one the gateway saw hold its uid (here: not the incarnation the
// upgrade bound the uid's 1.0.3 identities to) is keyed on its account
// incarnation; its 1.0.3 identity is not. The 1.0.3 identity
// was derived with the incarnation too, so it matched no entry 1.0.3 wrote
// and an action/LOW assignment fell to the observe default. Now the 1.0.3
// identity is the one 1.0.3 derived, and as nothing proves the incarnation
// that holds the uid is the one 1.0.3 saw, the request gets the strictest
// profile that may apply, never the weaker default.
func TestIncarnationKeyedAgentKeepsItsLegacyAssignmentNeverWeaker(t *testing.T) {
	alice := profileSubject{UserID: "70001", UserName: "alice"}
	for _, account := range []string{"alice", "alice@corp.example"} {
		t.Run(account, func(t *testing.T) {
			b := newStrictBridge(t, account)
			in := b.inputs(70001, account)
			legacy := agentidentity.LegacyAgentID(in)
			previous := agentIdentityIncarnation
			t.Cleanup(func() { agentIdentityIncarnation = previous })
			agentIdentityIncarnation = func(string) string { return "record:5F1C0A1E-0000-4000-8000-000000000001" }
			facts := resolveHookAgentIdentity(b.peer(70001), agentHookRequest{ConnectorName: "codex"})
			if facts.ID == agentidentity.AgentID(in) || facts.ID == legacy {
				t.Fatalf("identity %q: want one keyed on the account incarnation", facts.ID)
			}
			if !strings.EqualFold(facts.LegacyID, legacy) {
				t.Fatalf("1.0.3 identity %q; want the one 1.0.3 derived, %q", facts.LegacyID, legacy)
			}
			// The account's name and a 1.0.3 record prove nothing for an
			// incarnation the gateway did not see first.
			stubLegacyProof(t, account, true)
			b.ledger([]inventory.AgentIdentityRecord{b.record(70001, legacy, account)})
			tight := map[string]config.GuardrailProfile{"tight": {Mode: "action", BlockAt: "low"}, "watch": {Mode: "observe"}}
			got, mode := b.hook(loop2Only(legacy, "tight", "watch", tight), 70001, alice)
			if got.Name != "tight" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
				t.Errorf("profile %+v, mode %q; want the entry's tight (action) as default_lookup_failed, never the observe default", got, mode)
			}
			got, _ = b.hook(loop2Only(legacy, "relaxed", "strict", loop2Incomparable), 70001, alice)
			loop2Unproven(t, "incomparable profiles", got)
			// Explain derives the claim from the ledger's record of the
			// identity, which names its incarnation.
			rec := b.record(70001, facts.ID, account)
			rec.UserIncarnation = "record:5F1C0A1E-0000-4000-8000-000000000001"
			b.ledger([]inventory.AgentIdentityRecord{b.record(70001, legacy, account), rec})
			set := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, loop2Only(legacy, "tight", "watch", tight)).guardrailProfileSet()
			if got := set.matchAgent(&alice, profileSubjectLookup, "codex", facts.ID, nil); got.Name != "tight" || got.Match != profileMatchDefaultLookupFailed {
				t.Errorf("explain: %+v; want tight as default_lookup_failed", got)
			}
		})
	}
}

// Review loop 2, finding 2. A 1.0.3 assignment of a qualified account whose
// 1.0.3 ledger record survived was unproven whatever proved the account:
// with profiles that do not cover each other, every hook it allowed before
// was refused. Its owner is proven now as a bare account's is: the account
// incarnation that holds the uid is the one 1.0.3 saw, and 1.0.3 named the
// account (domain included) as the host names it now. A namesake of
// another domain or without one, another spelling, or an unproven
// incarnation still leave it unproven.
func TestQualifiedLegacyAssignmentOfAProvenAccountKeepsWorking(t *testing.T) {
	const account = "alice@corp.example"
	alice := profileSubject{UserID: "70001", UserName: "alice"}
	setup := func(t *testing.T) (*strictBridge, string, string) {
		t.Helper()
		b := newStrictBridge(t, account)
		in := b.inputs(70001, account)
		stubLegacyProof(t, "", true)
		return b, agentidentity.LegacyAgentID(in), agentidentity.AgentID(in)
	}
	cfg := func(legacy string) *config.Config { return loop2Only(legacy, "relaxed", "strict", loop2Incomparable) }
	for name, records := range map[string]func(b *strictBridge, legacy, current string) []inventory.AgentIdentityRecord{
		"its 1.0.3 record": func(b *strictBridge, legacy, _ string) []inventory.AgentIdentityRecord {
			return []inventory.AgentIdentityRecord{b.record(70001, legacy, account)}
		},
		"its 1.0.3 and 1.0.4 records": func(b *strictBridge, legacy, current string) []inventory.AgentIdentityRecord {
			return []inventory.AgentIdentityRecord{b.record(70001, legacy, account), b.record(70001, current, account)}
		},
		"its 1.0.3 record in another case": func(b *strictBridge, legacy, _ string) []inventory.AgentIdentityRecord {
			return []inventory.AgentIdentityRecord{b.record(70001, legacy, "Alice@CORP.example")}
		},
		"another account's records": func(b *strictBridge, legacy, _ string) []inventory.AgentIdentityRecord {
			return []inventory.AgentIdentityRecord{b.record(70001, legacy, account), b.record(70002, "agt-0000000000000002", "alice@lab.example")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, legacy, current := setup(t)
			b.ledger(records(b, legacy, current))
			got, mode := b.hook(cfg(legacy), 70001, alice)
			loop2Kept(t, "hook", got, mode)
			set := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg(legacy)).guardrailProfileSet()
			if got := set.matchAgent(&alice, profileSubjectLookup, "codex", current, nil); got.Name != "relaxed" || got.Match != profileMatchAgent || got.Refused != "" {
				t.Errorf("explain: %+v; want relaxed as agent", got)
			}
		})
	}
	for name, tc := range map[string]struct {
		recorded []string // names of the uid's records; the first is the 1.0.3 one
		proof    string
		bound    bool
	}{
		"a namesake of another domain":     {recorded: []string{account, "alice@lab.example"}, bound: true},
		"a namesake without a domain":      {recorded: []string{account, "alice"}, bound: true},
		"1.0.3 spelled it with its domain": {recorded: []string{`CORP\alice`}, bound: true},
		"1.0.3 named it without a domain":  {recorded: []string{"alice"}, bound: true},
		"the incarnation is not proven":    {recorded: []string{account}},
		"the homes file named another":     {recorded: []string{account}, proof: "alice@lab.example", bound: true},
		"no 1.0.3 record or homes name":    {bound: true},
	} {
		t.Run(name, func(t *testing.T) {
			b, legacy, current := setup(t)
			stubLegacyProof(t, tc.proof, tc.bound)
			var records []inventory.AgentIdentityRecord
			for i, recorded := range tc.recorded {
				id := legacy
				if i > 0 {
					in := b.inputs(70001, recorded)
					id = agentidentity.AgentID(in)
				}
				records = append(records, b.record(70001, id, recorded))
			}
			if records == nil {
				records = []inventory.AgentIdentityRecord{b.record(70001, current, account)}
			}
			b.ledger(records)
			got, _ := b.hook(cfg(legacy), 70001, alice)
			loop2Unproven(t, "hook", got)
		})
	}
	t.Run("a namesake recorded later withdraws the proof", func(t *testing.T) {
		b, legacy, _ := setup(t)
		records := []inventory.AgentIdentityRecord{b.record(70001, legacy, account)}
		b.ledger(records)
		api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg(legacy))
		set := api.guardrailProfileSet()
		claim := func() (profileAgentClaim, bool) {
			return legacyAgentClaim(legacy, "70001", records[0].MachineHash, account, "", false), true
		}
		if got := set.matchAgent(&alice, profileSubjectVerified, "codex", agentidentity.AgentID(b.inputs(70001, account)), claim); got.Name != "relaxed" || got.Match != profileMatchAgent {
			t.Fatalf("before: %+v; want relaxed as agent", got)
		}
		b.ledger(append(records, b.record(70001, agentidentity.AgentID(b.inputs(70001, "alice@lab.example")), "alice@lab.example")))
		set.agentBridge.readAt = time.Time{}
		if got := set.matchAgent(&alice, profileSubjectVerified, "codex", agentidentity.AgentID(b.inputs(70001, account)), claim); got.Refused == "" {
			t.Errorf("after the namesake was recorded: %+v; want a refusal", got)
		}
	})
}

// Review loop 2, finding 3. A bare account's 1.0.3 assignment was proven
// only by its 1.0.3 ledger record, which a 1.0.3 prune of an idle agent
// removed and an unreadable ledger hides: incomparable profiles then
// refused a hook 1.0.3 allowed. The homes file the build before 1.0.4 kept
// names the account it derived the uid's identities for, so with the
// account incarnation proven the entry keeps applying whatever the ledger
// says; the ledger can only withdraw the proof (a namesake).
func TestBareLegacyAssignmentNeedsNoLedgerRowWhenTheHomesFileNamesTheAccount(t *testing.T) {
	alice := profileSubject{UserID: "70001", UserName: "alice"}
	setup := func(t *testing.T, proof string, bound bool) (*strictBridge, string, string) {
		t.Helper()
		b := newStrictBridge(t, "alice")
		in := b.inputs(70001, "alice")
		stubLegacyProof(t, proof, bound)
		return b, agentidentity.LegacyAgentID(in), agentidentity.AgentID(in)
	}
	cfg := func(legacy string) *config.Config { return loop2Only(legacy, "relaxed", "strict", loop2Incomparable) }
	for name, records := range map[string]func(b *strictBridge, current string) []inventory.AgentIdentityRecord{
		"the ledger cannot be read": func(*strictBridge, string) []inventory.AgentIdentityRecord { return nil },
		"1.0.3 pruned its record":   func(*strictBridge, string) []inventory.AgentIdentityRecord { return []inventory.AgentIdentityRecord{} },
		"only the 1.0.4 record is left": func(b *strictBridge, current string) []inventory.AgentIdentityRecord {
			return []inventory.AgentIdentityRecord{b.record(70001, current, "alice")}
		},
		"another uid's qualified records": func(b *strictBridge, _ string) []inventory.AgentIdentityRecord {
			return []inventory.AgentIdentityRecord{b.record(70002, "agt-0000000000000002", "alice@corp.example")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, legacy, current := setup(t, "alice", true)
			b.ledger(records(b, current))
			got, mode := b.hook(cfg(legacy), 70001, alice)
			loop2Kept(t, "hook", got, mode)
		})
	}
	for name, tc := range map[string]struct {
		proof   string
		bound   bool
		records func(b *strictBridge, legacy string) []inventory.AgentIdentityRecord
	}{
		"the incarnation is not proven":     {proof: "alice"},
		"the homes file named it qualified": {proof: "alice@corp.example", bound: true},
		"no homes name, the ledger unread":  {bound: true},
		"a qualified namesake held the uid": {proof: "alice", bound: true, records: func(b *strictBridge, legacy string) []inventory.AgentIdentityRecord {
			return []inventory.AgentIdentityRecord{b.record(70001, legacy, "alice@corp.example")}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			b, legacy, _ := setup(t, tc.proof, tc.bound)
			var records []inventory.AgentIdentityRecord
			if tc.records != nil {
				records = tc.records(b, legacy)
			}
			b.ledger(records)
			got, _ := b.hook(cfg(legacy), 70001, alice)
			loop2Unproven(t, "hook", got)
		})
	}
}

// A per-user gateway's own account is the one its 1.0.3 identities were
// derived for; an account incarnation other than the first one proves
// nothing whatever the homes file says.
func TestLegacyAgentClaimProof(t *testing.T) {
	stubLegacyProof(t, "alice", true)
	if got := legacyAgentClaim("AGT-1", "70001", "m", "alice@corp.example", "", true); !got.Bound || got.Name != "alice@corp.example" || got.ID != "agt-1" {
		t.Errorf("own account: %+v; want bound under its own name", got)
	}
	if got := legacyAgentClaim("agt-1", "70001", "m", "alice", "sid:S-1-5-21-1-2-3-4", false); got.Bound {
		t.Errorf("another incarnation: %+v; want unbound", got)
	}
	if got := legacyAgentClaim("agt-1", "70001", "m", "alice", "", false); !got.Bound || got.Name != "alice" {
		t.Errorf("proven first incarnation: %+v; want bound with the homes name", got)
	}
	if got := legacyAgentClaim("", "70001", "m", "alice", "", true); got.Bound {
		t.Errorf("no 1.0.3 identity: %+v; want no proof", got)
	}
}
