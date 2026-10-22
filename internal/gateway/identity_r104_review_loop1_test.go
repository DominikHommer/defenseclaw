// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review loop 1, finding 1. 1.0.4 gives a bare account an agent identity of
// its own (GAP-0424); 1.0.0 to 1.0.3 gave it the legacy one. Its 1.0.3
// agents assignment keeps applying after the upgrade when the agent ledger
// proves the entry is its own: the 1.0.3 record names that bare account and
// derives its current identity, and no record shows another domain's
// namesake of the uid. Before, the entry was unproven: the request fell to
// the strictest candidate or was refused where the entry's profile and the
// default enforce different rules. Anything short of that proof stays
// unproven.
func TestBareAccountKeepsItsOwnLegacyAgentAssignmentAfterUpgrade(t *testing.T) {
	alice := profileSubject{UserID: "70001", UserName: "alice"}
	setup := func(t *testing.T) (*strictBridge, string, string) {
		t.Helper()
		b := newStrictBridge(t, "alice")
		in := b.inputs(70001, "alice")
		legacy, current := agentidentity.LegacyAgentID(in), agentidentity.AgentID(in)
		if legacy == "" || legacy == current {
			t.Fatalf("legacy %q, current %q: want a bare account's distinct 1.0.3 identity", legacy, current)
		}
		return b, legacy, current
	}
	only := func(legacy, profile, defaultProfile string, profiles map[string]config.GuardrailProfile) *config.Config {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "observe"
		cfg.Guardrail.Profiles = profiles
		cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
			{Profile: profile, Match: config.ProfileMatch{Agents: []string{legacy}}},
		}
		cfg.Guardrail.DefaultProfile = defaultProfile
		return cfg
	}
	unproven := func(t *testing.T, what string, got profileDecision, mode string) {
		t.Helper()
		if got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
			t.Errorf("%s: profile %+v, mode %q; want strict (action) as default_lookup_failed", what, got, mode)
		}
	}

	t.Run("the entry's profile and the default enforce different rules", func(t *testing.T) {
		b, legacy, _ := setup(t)
		b.ledger([]inventory.AgentIdentityRecord{b.record(70001, legacy, "alice")})
		profiles := map[string]config.GuardrailProfile{
			"relaxed": {Mode: "action", BlockAt: "high", Sandbox: &config.OpenShellAdminConfig{EgressAllowOnly: []string{"pkg.example"}}},
			"strict":  {Mode: "action", BlockAt: "low"},
		}
		got, mode := b.hook(only(legacy, "relaxed", "strict", profiles), 70001, alice)
		if got.Name != "relaxed" || got.Match != profileMatchAgent || got.Refused != "" || mode != "action" {
			t.Errorf("profile %+v, mode %q; want the entry's relaxed (action) as agent, not refused", got, mode)
		}
	})
	t.Run("an observe entry over a strict default", func(t *testing.T) {
		b, legacy, _ := setup(t)
		b.ledger([]inventory.AgentIdentityRecord{b.record(70001, legacy, "alice")})
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "watch", "watch", "strict"), 70001, alice)
		if got.Name != "watch" || got.Match != profileMatchAgent || mode != "observe" {
			t.Errorf("profile %+v, mode %q; want the entry's watch (observe) as agent, as 1.0.3 gave it", got, mode)
		}
	})
	t.Run("a stricter later assignment still wins", func(t *testing.T) {
		b, legacy, _ := setup(t)
		b.ledger([]inventory.AgentIdentityRecord{b.record(70001, legacy, "alice")})
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "watch", "strict", "watch"), 70001, alice)
		if got.Name != "strict" || got.Match != profileMatchConnector || mode != "action" {
			t.Errorf("profile %+v, mode %q; want the stricter connector assignment", got, mode)
		}
	})
	t.Run("explain names the agent by its identity only", func(t *testing.T) {
		b, legacy, current := setup(t)
		b.ledger([]inventory.AgentIdentityRecord{b.record(70001, legacy, "alice")})
		set := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, strictBridgeConfig(strictBridgeModes, legacy, "watch", "watch", "strict")).guardrailProfileSet()
		got := set.matchAgent(&profileSubject{UserID: "70001", UserName: "alice"}, profileSubjectLookup, "codex", current, nil)
		if got.Name != "watch" || got.Match != profileMatchAgent {
			t.Errorf("explain: %+v; want watch as agent", got)
		}
	})
	t.Run("a namesake of another domain held the uid", func(t *testing.T) {
		b, legacy, _ := setup(t)
		corp := agentidentity.AgentID(b.inputs(70001, "alice@corp.example"))
		b.ledger([]inventory.AgentIdentityRecord{b.record(70001, legacy, "alice"), b.record(70001, corp, "alice@corp.example")})
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "watch", "watch", "strict"), 70001, alice)
		unproven(t, "namesake", got, mode)
	})
	t.Run("the 1.0.3 record names a qualified account", func(t *testing.T) {
		b, legacy, _ := setup(t)
		b.ledger([]inventory.AgentIdentityRecord{b.record(70001, legacy, `CORP\alice`)})
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "watch", "watch", "strict"), 70001, alice)
		unproven(t, "qualified record", got, mode)
	})
	t.Run("no 1.0.3 record", func(t *testing.T) {
		b, legacy, _ := setup(t)
		b.ledger([]inventory.AgentIdentityRecord{})
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "watch", "watch", "strict"), 70001, alice)
		unproven(t, "no record", got, mode)
	})
	t.Run("the ledger cannot be read", func(t *testing.T) {
		b, legacy, _ := setup(t)
		b.ledger(nil)
		got, mode := b.hook(strictBridgeConfig(strictBridgeModes, legacy, "watch", "watch", "strict"), 70001, alice)
		unproven(t, "unreadable ledger", got, mode)
	})
	t.Run("another account took the uid over", func(t *testing.T) {
		b, legacy, _ := setup(t)
		b.ledger([]inventory.AgentIdentityRecord{b.record(70001, legacy, "alice")})
		previous := agentIdentityIncarnation
		t.Cleanup(func() { agentIdentityIncarnation = previous })
		agentIdentityIncarnation = func(string) string { return "sid:S-1-5-21-1-2-3-4242" }
		got, _ := b.hook(only(legacy, "watch", "strict", strictBridgeModes), 70001, alice)
		if got.Name != "strict" || got.Match == profileMatchAgent {
			t.Errorf("replacement holder: %+v; want the strict default, never the former holder's entry", got)
		}
	})
	t.Run("a namesake recorded later withdraws the proof", func(t *testing.T) {
		b, legacy, current := setup(t)
		records := []inventory.AgentIdentityRecord{b.record(70001, legacy, "alice")}
		previous := profileAgentLedger
		t.Cleanup(func() { profileAgentLedger = previous })
		profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) {
			return slices.Clone(records), true
		}
		set := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, strictBridgeConfig(strictBridgeModes, legacy, "watch", "watch", "strict")).guardrailProfileSet()
		subject := profileSubject{UserID: "70001", UserName: "alice"}
		if got := set.matchAgent(&subject, profileSubjectVerified, "codex", current, nil); got.Name != "watch" || got.Match != profileMatchAgent {
			t.Fatalf("before: %+v; want watch as agent", got)
		}
		records = append(records, b.record(70001, agentidentity.AgentID(b.inputs(70001, "alice@corp.example")), "alice@corp.example"))
		set.agentBridge.readAt = time.Time{}
		if got := set.matchAgent(&subject, profileSubjectVerified, "codex", current, nil); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed {
			t.Errorf("after the namesake was recorded: %+v; want strict as default_lookup_failed (no memoised proof)", got)
		}
	})
}

// Review loop 1, finding 2. Two proven assignments match one user and
// their profiles enforce different rules: one denies sandbox use, the other
// blocks from a lower block_at but allows sandboxes. Before, the one with
// the lower block_at applied and the sandbox denial was gone. No profile is
// the strictest of the two, so the first listed applies, as every release
// before 1.0.4 chose; a profile another one covers never does. The same
// holds when an unproven assignment is also in play.
func TestProvenMatchesThatEnforceDifferentRulesKeepTheFirstListed(t *testing.T) {
	p := identityTestPlatforms[0]
	no := false
	profiles := map[string]config.GuardrailProfile{
		"nosandbox": {Mode: "action", BlockAt: "HIGH", Sandbox: &config.OpenShellAdminConfig{Allowed: &no}},
		"lowblock":  {Mode: "action", BlockAt: "LOW"},
		"asks":      {Mode: "action", BlockAt: "HIGH", HILT: &config.HILTConfig{Enabled: true, MinSeverity: "MEDIUM"}},
		"strict":    {Mode: "action", BlockAt: "LOW"},
		"watch":     {Mode: "observe"},
		"floor":     {Mode: "observe", Sandbox: &config.OpenShellAdminConfig{Allowed: &no}},
	}
	user := func(profile string) config.ProfileAssignment {
		return config.ProfileAssignment{Profile: profile, Match: config.ProfileMatch{Users: []string{p.id}}}
	}
	group := func(profile string) config.ProfileAssignment {
		return config.ProfileAssignment{Profile: profile, Match: config.ProfileMatch{Groups: []string{p.group}}}
	}
	connector := func(profile string) config.ProfileAssignment {
		return config.ProfileAssignment{Profile: profile, Match: config.ProfileMatch{Connectors: []string{"codex"}}}
	}
	upn := func(profile string) config.ProfileAssignment {
		return config.ProfileAssignment{Profile: profile, Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}}
	}
	for _, tc := range []struct {
		name        string
		def         string
		assignments []config.ProfileAssignment
		upnUnproven bool
		want, match string
	}{
		{"sandbox denial first", "watch", []config.ProfileAssignment{user("nosandbox"), group("lowblock")}, false, "nosandbox", profileMatchUser},
		{"lower block_at first", "watch", []config.ProfileAssignment{group("lowblock"), user("nosandbox")}, false, "lowblock", profileMatchGroup},
		{"a HILT first", "watch", []config.ProfileAssignment{user("asks"), group("lowblock")}, false, "asks", profileMatchUser},
		{"a covered profile listed first never applies", "watch",
			[]config.ProfileAssignment{group("watch"), user("nosandbox"), connector("lowblock")}, false, "nosandbox", profileMatchUser},
		{"comparable profiles: the strictest, whatever the order", "watch",
			[]config.ProfileAssignment{user("watch"), group("strict")}, false, "strict", profileMatchGroup},
		{"with an unproven assignment the proven choice covers", "floor",
			[]config.ProfileAssignment{user("nosandbox"), group("lowblock"), upn("nosandbox")}, true, "nosandbox", profileMatchUser},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "observe"
			cfg.Guardrail.Profiles = profiles
			cfg.Guardrail.ProfileAssignments = tc.assignments
			cfg.Guardrail.DefaultProfile = tc.def
			set, err := newGuardrailProfileSet(cfg, nil, true)
			if err != nil || set == nil {
				t.Fatalf("profile set: %v", err)
			}
			subject := identityTestSubject(p, p.providers[1], stateProven, true)
			subject.upnUnproven = tc.upnUnproven
			got := set.match(&subject, profileSubjectVerified, "codex", "")
			if got.Name != tc.want || got.Match != tc.match || got.Refused != "" {
				t.Errorf("%+v; want %s as %s, not refused", got, tc.want, tc.match)
			}
		})
	}
}

// Review loop 1, finding 4. A refusal names every fact it could not prove
// and the step that proves it. On guardian-backed Linux and macOS the
// account and its groups can be proven while the UPN awaits the guardian's
// record: the refusal said "DefenseClaw refused this request: , and ..."
// with a directory-recovery hint. Each unproven fact has its own reason and
// recovery step.
func TestRefusalNamesEachUnprovenFactAndItsRecovery(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"upn-strict": {Mode: "action", BlockAt: "LOW", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
		"default":    {Mode: "action", BlockAt: "HIGH"},
	}
	cfg.Guardrail.DefaultProfile = "default"
	set := func(t *testing.T, match config.ProfileMatch) *guardrailProfileSet {
		t.Helper()
		cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "upn-strict", Match: match}}
		s, err := newGuardrailProfileSet(cfg, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	upnEntry := config.ProfileMatch{Users: []string{"alice@corp.example"}}
	for _, tc := range []struct {
		name     string
		platform identityTestPlatform
		provider identityTestProvider
		state    string
		upn      bool
		match    config.ProfileMatch
		agent    bool
		want     []string
		not      []string
	}{
		{"linux sssd, only the UPN", identityTestPlatforms[0], identityTestPlatforms[0].providers[1], stateProven, true, upnEntry, false,
			[]string{"UPN", "guardian writes this account's identity record"}, []string{"directory recovers", "request: ,"}},
		{"macOS open directory, only the UPN", identityTestPlatforms[1], identityTestPlatforms[1].providers[0], stateProven, true, upnEntry, false,
			[]string{"UPN", "guardian writes this account's identity record"}, []string{"directory recovers", "request: ,"}},
		{"the UPN and the groups", identityTestPlatforms[0], identityTestPlatforms[0].providers[1], stateGroupsUnknown, true,
			config.ProfileMatch{Groups: []string{"eng-strict"}}, false,
			[]string{"UPN", "group membership", "directory recovers", "guardian writes"}, []string{"request: ,"}},
		{"the account", identityTestPlatforms[0], identityTestPlatforms[0].providers[1], stateUnknown, false, upnEntry, false,
			[]string{"which account this is", "directory recovers"}, []string{"UPN", "request: ,"}},
		{"only the agent entry", identityTestPlatforms[0], identityTestPlatforms[0].providers[1], stateProven, false,
			config.ProfileMatch{Agents: []string{"agt-00000000000000aa"}}, true,
			[]string{"agent identity from before the upgrade", "ask your administrator"}, []string{"directory recovers", "UPN", "request: ,"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := set(t, tc.match)
			subject := identityTestSubject(tc.platform, tc.provider, tc.state, false)
			subject.upnUnproven = tc.upn
			var unresolved func(string) bool
			if tc.agent {
				unresolved = func(entry string) bool { return entry == "agt-00000000000000aa" }
			}
			got := s.selectProfile(&subject, resolveIdentity(&subject, unresolved), profileSubjectVerified, "codex", "agt-00000000000000bb")
			if got.Refused == "" {
				t.Fatalf("%+v; want a refusal", got)
			}
			for _, want := range tc.want {
				if !strings.Contains(got.Refused, want) {
					t.Errorf("refusal %q does not say %q", got.Refused, want)
				}
			}
			for _, not := range tc.not {
				if strings.Contains(got.Refused, not) {
					t.Errorf("refusal %q says %q", got.Refused, not)
				}
			}
			if strings.Count(got.Refused, "directory recovers") > 1 {
				t.Errorf("refusal %q repeats a step", got.Refused)
			}
		})
	}
}

// Review loop 1, finding 3. A caller whose profile decision is refused has
// no profile of its own, and the decision's Name is only the strictest
// candidate, which may be another account's (an assignment that may name
// the caller while its facts are unproven). Settings, policy/explain,
// policy/test and policy/packs answered with that profile: its
// description, egress policy and decisions. Each now answers the refusal
// alone; a live registration keeps its own profile through a re-match.
func TestSandboxPolicyViewsOfARefusedDecisionNameNoProfile(t *testing.T) {
	const secret = "bob-internal.example"
	setup := func(t *testing.T) *sandboxFixture {
		t.Helper()
		f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
		f.cfg.Guardrail.Profiles["bob-only"] = config.GuardrailProfile{Description: "Bob private profile", Mode: "action",
			Sandbox: &config.OpenShellAdminConfig{EgressAllowOnly: []string{secret}}}
		f.cfg.Guardrail.ProfileAssignments = append([]config.ProfileAssignment{
			{Profile: "bob-only", Match: config.ProfileMatch{Users: []string{sbxBob.Name}}},
			{Profile: "bob-only", Match: config.ProfileMatch{Groups: []string{"dc-sbx-bob-team"}}},
		}, f.cfg.Guardrail.ProfileAssignments...)
		f.publishFirstGeneration()
		return f
	}
	groupsUnknown := func(f *sandboxFixture, peer managedHookPeer) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.facts[peer.UID] = useridentity.DirectoryFacts{
			Principal: peer.Name + "@DCLAB.TEST", Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
			Source: "sssd", GroupsPartial: true, ResolvedAt: time.Now(),
		}
	}
	leaks := func(body string) bool {
		return strings.Contains(body, "bob-only") || strings.Contains(body, "Bob private") || strings.Contains(body, secret)
	}
	views := func(t *testing.T, f *sandboxFixture, header map[string]string, registration string) {
		t.Helper()
		for _, call := range []struct {
			name, method, path string
			body               any
		}{
			{"settings", http.MethodGet, sandboxrelay.PathSettings, nil},
			{"explain", http.MethodPost, sandboxrelay.PathPolicyExplain, sandboxrelay.ExplainRequest{V: 1, Connector: "claudecode", Registration: registration}},
			{"test", http.MethodPost, sandboxrelay.PathPolicyTest, sandboxrelay.PolicyTestRequest{V: 1, Checks: []sandboxapi.PolicyCheck{{Host: "pkg.example", Port: 443}}}},
			{"packs", http.MethodGet, sandboxrelay.PathPolicyPacks, nil},
		} {
			rec := f.do(sbxAlice, call.method, call.path, call.body, header)
			if registration == "" && rec.Code == http.StatusOK {
				t.Errorf("%s: %d %s; want the refusal", call.name, rec.Code, rec.Body.String())
			}
			if leaks(rec.Body.String()) {
				t.Errorf("%s: %d %s names another account's profile", call.name, rec.Code, rec.Body.String())
			}
		}
	}
	t.Run("account lookup failed", func(t *testing.T) {
		f := setup(t)
		// explain, test and packs wait identityDirectoryBudget for the lookup.
		f.coldCache(sbxAlice)
		views(t, f, map[string]string{sandboxrelay.ConnectorHeader: "claudecode"}, "")
	})
	t.Run("groups unknown", func(t *testing.T) {
		f := setup(t)
		groupsUnknown(f, sbxAlice)
		views(t, f, map[string]string{sandboxrelay.ConnectorHeader: "claudecode"}, "")
	})
	t.Run("a live registration re-matched while refused", func(t *testing.T) {
		f := setup(t)
		f.setGroups(sbxAlice, "dc-sbx-contractors")
		resp := f.live(sbxAlice, 1)
		if resp.Registration.Provisional || resp.Banner.Profile != "contractors" {
			t.Fatalf("create: %+v %+v", resp.Registration, resp.Banner)
		}
		groupsUnknown(f, sbxAlice)
		views(t, f, map[string]string{sandboxrelay.ConnectorHeader: "claudecode", sandboxrelay.RegistrationHeader: resp.Registration.ID}, resp.Registration.ID)
		auth, _ := f.api.sandboxAuth()
		reg, ok, err := auth.store.Get(sbxAlice.UID, resp.Registration.ID)
		if err != nil || !ok || reg.Profile != "contractors" || reg.State != sandboxreg.StateLive {
			t.Errorf("registration after the refused re-match: %+v (%v); want contractors, live", reg, err)
		}
	})
}
