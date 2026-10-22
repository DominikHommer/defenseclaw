// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// orderBridgeConfig assigns legacyProfile to the agents entry legacy and
// currentProfile to the agents entry current, legacy first when
// legacyFirst; the default is defaultProfile.
func orderBridgeConfig(profiles map[string]config.GuardrailProfile, legacy, legacyProfile, current, currentProfile string, legacyFirst bool, defaultProfile string) *config.Config {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = profiles
	old := config.ProfileAssignment{Profile: legacyProfile, Match: config.ProfileMatch{Agents: []string{legacy}}}
	now := config.ProfileAssignment{Profile: currentProfile, Match: config.ProfileMatch{Agents: []string{current}}}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{now, old}
	if legacyFirst {
		cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{old, now}
	}
	cfg.Guardrail.DefaultProfile = defaultProfile
	return cfg
}

// An assignment naming an agent's current identity does not skip the
// assignments before it that name the agent's 1.0.3 identity: both
// identities are matched in assignment order, as 1.0.3 matched the agent's
// one identity. A proven entry that comes first applies. An unproven one
// that comes first gets the strictest profile that may apply, or a
// refusal, never the later row's weaker profile.
func TestLegacyAgentAssignmentKeepsItsPlaceBeforeACurrentIdentityAssignment(t *testing.T) {
	alice := profileSubject{UserID: "70001", UserName: "alice"}
	setup := func(t *testing.T) (b *strictBridge, legacy, corp string) {
		b = newStrictBridge(t, "alice@corp.example")
		in := b.inputs(70001, "alice@corp.example")
		return b, agentidentity.LegacyAgentID(in), agentidentity.AgentID(in)
	}
	expect := func(t *testing.T, got profileDecision, mode, name, match, wantMode string, refused bool) {
		t.Helper()
		if got.Name != name || got.Match != match || mode != wantMode || got.Refused != refused {
			t.Errorf("profile %+v, mode %q; want %s (%s) as %s, refused %v", got, mode, name, wantMode, match, refused)
		}
	}
	proven := func(b *strictBridge, legacy, corp string) {
		b.ledger([]inventory.AgentIdentityRecord{
			b.record(70001, legacy, "alice@corp.example"), b.record(70001, corp, "alice@corp.example"),
		})
	}

	t.Run("proven entry first", func(t *testing.T) {
		b, legacy, corp := setup(t)
		proven(b, legacy, corp)
		got, mode := b.hook(orderBridgeConfig(strictBridgeModes, legacy, "strict", corp, "watch", true, "watch"), 70001, alice)
		expect(t, got, mode, "strict", profileMatchAgent, "action", false)
		if got.Assignment != 1 {
			t.Errorf("assignment %d, want the first", got.Assignment)
		}
	})
	t.Run("proven entry first, directory lookup failed", func(t *testing.T) {
		b, legacy, corp := setup(t)
		proven(b, legacy, corp)
		failed := alice
		failed.LookupFailed = true
		got, mode := b.hook(orderBridgeConfig(strictBridgeModes, legacy, "strict", corp, "watch", true, "watch"), 70001, failed)
		expect(t, got, mode, "strict", profileMatchAgent, "action", false)
	})
	t.Run("proven entry first, groups unknown", func(t *testing.T) {
		b, legacy, corp := setup(t)
		proven(b, legacy, corp)
		unknown := alice
		unknown.GroupsUnknown = true
		got, mode := b.hook(orderBridgeConfig(strictBridgeModes, legacy, "strict", corp, "watch", true, "watch"), 70001, unknown)
		expect(t, got, mode, "strict", profileMatchAgent, "action", false)
	})
	t.Run("proven entry second", func(t *testing.T) {
		b, legacy, corp := setup(t)
		proven(b, legacy, corp)
		got, mode := b.hook(orderBridgeConfig(strictBridgeModes, legacy, "strict", corp, "watch", false, "watch"), 70001, alice)
		expect(t, got, mode, "watch", profileMatchAgent, "observe", false)
	})
	t.Run("ledger cannot be read", func(t *testing.T) {
		b, legacy, corp := setup(t)
		b.ledger(nil)
		got, mode := b.hook(orderBridgeConfig(strictBridgeModes, legacy, "strict", corp, "watch", true, "watch"), 70001, alice)
		expect(t, got, mode, "strict", profileMatchDefaultLookupFailed, "action", false)
	})
	t.Run("ledger cannot be read, directory lookup failed", func(t *testing.T) {
		b, legacy, corp := setup(t)
		b.ledger(nil)
		failed := alice
		failed.LookupFailed = true
		got, mode := b.hook(orderBridgeConfig(strictBridgeModes, legacy, "strict", corp, "watch", true, "watch"), 70001, failed)
		expect(t, got, mode, "strict", profileMatchDefaultLookupFailed, "action", false)
	})
	t.Run("namesakes of two domains", func(t *testing.T) {
		b, legacy, corp := setup(t)
		b.ledger([]inventory.AgentIdentityRecord{
			b.record(70001, legacy, "alice@lab.example"), b.record(70001, corp, "alice@corp.example"),
		})
		got, mode := b.hook(orderBridgeConfig(strictBridgeModes, legacy, "strict", corp, "watch", true, "watch"), 70001, alice)
		expect(t, got, mode, "strict", profileMatchDefaultLookupFailed, "action", false)
	})
	t.Run("1.0.3 record pruned before the upgrade", func(t *testing.T) {
		b, legacy, corp := setup(t)
		b.ledger([]inventory.AgentIdentityRecord{b.record(70001, corp, "alice@corp.example")})
		got, mode := b.hook(orderBridgeConfig(strictBridgeModes, legacy, "strict", corp, "watch", true, "watch"), 70001, alice)
		expect(t, got, mode, "strict", profileMatchDefaultLookupFailed, "action", false)
	})
	t.Run("an unproven entry first that the later row does not cover is refused", func(t *testing.T) {
		b, legacy, corp := setup(t)
		b.ledger(nil)
		profiles := map[string]config.GuardrailProfile{
			"entry":   {Mode: "action", BlockAt: "high", RulePack: "strict"},
			"current": {Mode: "action", BlockAt: "high", RulePack: "permissive"},
		}
		got, mode := b.hook(orderBridgeConfig(profiles, legacy, "entry", corp, "current", true, "entry"), 70001, alice)
		expect(t, got, mode, "entry", profileMatchDefaultLookupFailed, "action", true)
	})
	t.Run("an unproven entry second", func(t *testing.T) {
		b, legacy, corp := setup(t)
		b.ledger(nil)
		got, mode := b.hook(orderBridgeConfig(strictBridgeModes, legacy, "strict", corp, "watch", false, "strict"), 70001, alice)
		expect(t, got, mode, "watch", profileMatchAgent, "observe", false)
	})
	t.Run("another account's current identity", func(t *testing.T) {
		// Its own 1.0.3 identity is derived with its request and no entry
		// names it: its assignment applies, even before the ledger answers.
		b, legacy, _ := setup(t)
		bob := agentidentity.AgentID(b.inputs(70002, "u70002@corp.example"))
		b.ledger(nil)
		got, mode := b.hook(orderBridgeConfig(strictBridgeModes, legacy, "strict", bob, "watch", true, "strict"), 70002,
			profileSubject{UserID: "70002", UserName: "u70002"})
		expect(t, got, mode, "watch", profileMatchAgent, "observe", false)
	})
	t.Run("explain, proven entry first", func(t *testing.T) {
		b, legacy, corp := setup(t)
		proven(b, legacy, corp)
		cfg := orderBridgeConfig(strictBridgeModes, legacy, "strict", corp, "watch", true, "watch")
		set := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg).guardrailProfileSet()
		got := set.matchAgent(&profileSubject{UserID: "70001", UserName: "x"}, profileSubjectLookup, "codex", corp, nil)
		if got.Name != "strict" || got.Match != profileMatchAgent || got.Assignment != 1 {
			t.Errorf("explain: %+v; want the 1.0.3 assignment strict", got)
		}
	})
	t.Run("explain, unrecorded agent", func(t *testing.T) {
		b, legacy, corp := setup(t)
		b.ledger([]inventory.AgentIdentityRecord{})
		cfg := orderBridgeConfig(strictBridgeModes, legacy, "strict", corp, "watch", true, "watch")
		set := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg).guardrailProfileSet()
		got := set.matchAgent(&profileSubject{UserID: "70001", UserName: "x"}, profileSubjectLookup, "codex", corp, nil)
		if got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed {
			t.Errorf("explain: %+v; want strict as default_lookup_failed", got)
		}
	})
}

// agentEntryMatches matches an agents entry against each identity of
// match's agent argument, never an empty one.
func TestAgentEntryMatchesEachIdentity(t *testing.T) {
	both := profileAgentIDs("agt-current", "agt-legacy")
	for _, tc := range []struct {
		entry, agent string
		want         bool
	}{
		{"agt-current", both, true},
		{" AGT-LEGACY ", both, true},
		{"agt-other", both, false},
		{"agt-current", "agt-current", true},
		{"", "", false},
		{"", both, false},
		{"agt-current", "", false},
	} {
		if got := agentEntryMatches(tc.entry, tc.agent); got != tc.want {
			t.Errorf("agentEntryMatches(%q, %q) = %v, want %v", tc.entry, tc.agent, got, tc.want)
		}
	}
}

// Explain refuses an agent argument with the separator of
// profileAgentIDs: it would be matched as each identity it joins.
func TestExplainRefusesAnAgentThatJoinsIdentities(t *testing.T) {
	b := newStrictBridge(t, "alice@corp.example")
	in := b.inputs(70001, "alice@corp.example")
	legacy, corp := agentidentity.LegacyAgentID(in), agentidentity.AgentID(in)
	b.ledger([]inventory.AgentIdentityRecord{})
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, orderBridgeConfig(strictBridgeModes, legacy, "strict", corp, "watch", false, "strict"))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?connector=codex&agent="+url.QueryEscape("agt-x"+profileAgentIDSep+corp), nil)
	req.RemoteAddr = "127.0.0.1:40000"
	rec := httptest.NewRecorder()
	api.handleGuardrailProfileResolve(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status %d body %s; want 400", rec.Code, rec.Body.String())
	}
}
