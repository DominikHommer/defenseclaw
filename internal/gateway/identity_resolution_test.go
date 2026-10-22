// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// identityTestPlatform is one platform's way of naming an account and its
// strict group: the ID kind, the directory providers that answer for it,
// and how a group entry is written there.
type identityTestPlatform struct {
	os        string
	id        string
	kind      string
	name      string
	group     string
	providers []identityTestProvider
}

type identityTestProvider struct {
	source    string
	directory useridentity.Directory
	domain    string
	sid       string
	// record is a macOS account's local node record
	// (DirectoryFacts.AccountRecord).
	record string
}

// keyed reports whether a proven account of the provider names its
// incarnation: by a SID, a macOS local node record, or its Windows SID. An
// account no token names keeps nothing proven (review loop 3).
func (provider identityTestProvider) keyed(p identityTestPlatform) bool {
	return provider.sid != "" || provider.record != "" || p.kind == useridentity.KindWindowsSID
}

var identityTestPlatforms = []identityTestPlatform{
	{os: "linux", id: "70001", kind: useridentity.KindPOSIXUID, name: "alice", group: "eng-strict", providers: []identityTestProvider{
		{source: useridentity.SourceNSSFiles, directory: useridentity.DirectoryLocal},
		{source: useridentity.SourceSSSD, directory: useridentity.DirectoryActiveDirectory, domain: "corp.example", sid: "S-1-5-21-1-2-3-1601"},
		{source: useridentity.SourceNSSLDAP, directory: useridentity.DirectoryLDAP, domain: "corp.example"},
		{source: useridentity.SourceWinbind, directory: useridentity.DirectoryActiveDirectory, domain: "corp.example", sid: "S-1-5-21-1-2-3-1602"},
	}},
	{os: "darwin", id: "501", kind: useridentity.KindPOSIXUID, name: "alice", group: "eng-strict", providers: []identityTestProvider{
		// A mobile account (a local node record), a local account, and a
		// network account with no local record.
		{source: useridentity.SourceMacOSOpenDirectory, directory: useridentity.DirectoryActiveDirectory, domain: "corp.example", record: "record:0a1b2c"},
		{source: useridentity.SourceMacOSOpenDirectory, directory: useridentity.DirectoryLocal, record: "record:3d4e5f"},
		{source: useridentity.SourceMacOSOpenDirectory, directory: useridentity.DirectoryActiveDirectory, domain: "corp.example"},
	}},
	{os: "windows", id: "S-1-5-21-9-9-9-1105", kind: useridentity.KindWindowsSID, name: `CORP\alice`, group: "S-1-5-21-9-9-9-2201",
		providers: []identityTestProvider{
			{source: useridentity.SourceWindowsLSA, directory: useridentity.DirectoryActiveDirectory, domain: "corp.example"},
			{source: useridentity.SourceWindowsIdentityStore, directory: useridentity.DirectoryEntraID, domain: "corp.example"},
		}},
}

// The proof states of one pass, as the verified subject carries them.
const (
	stateProven         = "proven"
	stateStale          = "stale"
	stateUnknown        = "unknown"
	stateFailed         = "failed"
	stateGroupsUnknown  = "groups-unknown"
	stateGroupsUnproven = "groups-unconfirmed"
)

func identityTestSubject(p identityTestPlatform, provider identityTestProvider, state string, inGroup bool) profileSubject {
	facts := useridentity.DirectoryFacts{
		Directory: provider.directory, Source: provider.source, Domain: provider.domain,
		Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(), AccountSID: provider.sid,
		AccountRecord: provider.record,
	}
	if inGroup {
		facts.Groups = []string{p.group, "everyone"}
	} else {
		facts.Groups = []string{"everyone"}
	}
	switch state {
	case stateUnknown, stateFailed:
		facts = useridentity.DirectoryFacts{}
	case stateGroupsUnknown:
		facts.Groups, facts.GroupsPartial = nil, true
	case stateGroupsUnproven:
		facts.Groups = []string{"7000", "everyone"}
		facts.UnconfirmedGroups = []string{"7000"}
	}
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: p.id, IDKind: p.kind, UserName: p.name, Directory: facts,
		Source: subjectSourcePeerCredentials}, true)
	switch state {
	case stateStale:
		subject.cachedFactsAge = 20 * time.Minute
	case stateFailed:
		subject.LookupError = "unixidentity: uid " + p.id + " is held by more than one account"
	}
	return subject
}

func identityTestSet(t *testing.T, p identityTestPlatform, defaultProfile string, assignments ...config.ProfileAssignment) *guardrailProfileSet {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict":  {Mode: "action", BlockAt: "LOW"},
		"tooling": {Mode: "action", BlockAt: "HIGH"},
		"watch":   {Mode: "observe"},
	}
	cfg.Guardrail.ProfileAssignments = assignments
	cfg.Guardrail.DefaultProfile = defaultProfile
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil || set == nil {
		t.Fatalf("profile set: %v", err)
	}
	return set
}

// TestResolveIdentityProofStatesAcrossProvidersAndPlatforms is the table
// of resolveIdentity: every proof state of a pass, for every directory
// provider, on Linux, macOS and Windows, and the profile the one selection
// rule gives it with a strict group assignment over a weaker default. A
// fact not proven never selects the weaker default.
func TestResolveIdentityProofStatesAcrossProvidersAndPlatforms(t *testing.T) {
	type want struct {
		account, groups proofStatus
		keyed           bool
		profile, match  string
	}
	for _, p := range identityTestPlatforms {
		for _, provider := range p.providers {
			for _, tc := range []struct {
				state   string
				inGroup bool
				want    want
			}{
				{stateProven, true, want{proofProven, proofProven, true, "strict", profileMatchGroup}},
				{stateProven, false, want{proofProven, proofProven, true, "watch", profileMatchDefault}},
				// explain serves the cached facts its hooks still apply
				// (cachedFactsAge): within their TTL they are proven, so
				// explain and hooks agree.
				{stateStale, true, want{proofProven, proofProven, true, "strict", profileMatchGroup}},
				{stateUnknown, true, want{proofUnknown, proofUnknown, false, "strict", profileMatchDefaultLookupFailed}},
				{stateFailed, true, want{proofFailed, proofUnknown, false, "strict", profileMatchDefaultLookupFailed}},
				{stateGroupsUnknown, true, want{proofProven, proofUnknown, true, "strict", profileMatchDefaultLookupFailed}},
				{stateGroupsUnproven, true, want{proofProven, proofUnknown, true, "strict", profileMatchDefaultLookupFailed}},
			} {
				name := p.os + "/" + provider.source + "/" + string(provider.directory) + "/" + tc.state
				t.Run(name, func(t *testing.T) {
					subject := identityTestSubject(p, provider, tc.state, tc.inGroup)
					res := resolveIdentity(&subject, nil)
					if tc.state == stateFailed && res.Groups == proofUnknown {
						tc.want.groups = proofUnknown
					}
					if res.Account != tc.want.account || res.Groups != tc.want.groups || res.Agent != proofProven {
						t.Fatalf("resolution %+v; want account %s, groups %s", res, tc.want.account, tc.want.groups)
					}
					if tc.want.keyed && !provider.keyed(p) {
						tc.want.keyed = false
					}
					if (res.Incarnation.key() != "") != tc.want.keyed {
						t.Fatalf("incarnation %+v keyed %v; want keyed %v", res.Incarnation, res.Incarnation.key() != "", tc.want.keyed)
					}
					if p.kind == useridentity.KindWindowsSID && tc.want.keyed && res.Incarnation.Token == "" {
						t.Fatalf("a Windows SID names its own incarnation: %+v", res.Incarnation)
					}
					set := identityTestSet(t, p, "watch",
						config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}})
					got := set.selectProfile(&subject, res, profileSubjectVerified, "codex", "")
					if got.Name != tc.want.profile || got.Match != tc.want.match {
						t.Fatalf("decision %+v; want %s (%s)", got, tc.want.profile, tc.want.match)
					}
					if tc.want.account != proofProven || tc.want.groups != proofProven {
						if len(got.Unproven) == 0 || !slices.Contains(got.Candidates, "strict") {
							t.Fatalf("unproven decision %+v names no unproven fact or candidate", got)
						}
					}
				})
			}
		}
	}
}

// When the profiles that may apply do not cover each other, their meet
// applies: never a refusal, and never the weaker of them.
func TestUnprovenFactsWithIncomparableProfilesApplyTheirMeet(t *testing.T) {
	p := identityTestPlatforms[0]
	cfg := &config.Config{}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict":  {Mode: "action", BlockAt: "LOW", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
		"default": {Mode: "action", BlockAt: "HIGH"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}}}
	cfg.Guardrail.DefaultProfile = "default"
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	subject := identityTestSubject(p, p.providers[1], stateUnknown, true)
	got := set.match(&subject, profileSubjectVerified, "codex", "")
	if got.Name != config.ProfileMeetName([]string{"default", "strict"}) || got.Match != profileMatchDefaultLookupFailed {
		t.Fatalf("decision %+v; want the meet of default and strict", got)
	}
	derived, ok := set.derivedProfile(got.Name)
	if !ok || hookModeForConfig(derived.Config, "codex") != "action" || resolveThresholds(derived.Config, "codex").Block != "LOW" ||
		!slices.Contains(derived.Sandbox.RequiredFor, "codex") {
		t.Fatalf("meet %+v; want action, block_at LOW and codex required in a sandbox", derived)
	}
}

// GAP-0323: a cold lookup timeout or a directory outage with a strict group
// assignment before a weaker default selected default_lookup_failed and
// the weaker default. It now selects the strictest profile that may apply.
func TestGAP0323LookupFailureNeverSelectsAWeakerDefault(t *testing.T) {
	p := identityTestPlatforms[0]
	set := identityTestSet(t, p, "watch",
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}})
	failed := profileSubject{UserID: p.id, IDKind: p.kind, LookupFailed: true}
	if got := set.match(&failed, profileSubjectVerified, "codex", ""); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed {
		t.Fatalf("failed lookup selected %+v; want strict", got)
	}
	// A uid assignment needs no directory and still applies; the failed
	// lookup cannot make the account weaker than it either.
	set = identityTestSet(t, p, "watch",
		config.ProfileAssignment{Profile: "tooling", Match: config.ProfileMatch{Users: []string{p.id}}},
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}})
	if got := set.match(&failed, profileSubjectVerified, "codex", ""); got.Name != "strict" {
		t.Fatalf("a uid assignment before an unknown group selected %+v; want strict (strictest regardless of order)", got)
	}
}

// GAP-0402: an earlier user-name or connector-only assignment must not hide
// a later group assignment whose membership is unknown; a proved other uid
// or another connector does.
func TestGAP0402UnknownMembershipIsNotHiddenByEarlierAssignments(t *testing.T) {
	p := identityTestPlatforms[0]
	failed := profileSubject{UserID: p.id, IDKind: p.kind, LookupFailed: true}
	unknownGroups := identityTestSubject(p, p.providers[1], stateGroupsUnknown, true)
	for _, first := range []config.ProfileMatch{{Users: []string{"alice"}}, {Connectors: []string{"codex"}}} {
		set := identityTestSet(t, p, "watch",
			config.ProfileAssignment{Profile: "watch", Match: first},
			config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"ldap-privileged"}}})
		for _, subject := range []profileSubject{failed, unknownGroups} {
			if got := set.match(&subject, profileSubjectVerified, "codex", ""); got.Name != "strict" {
				t.Fatalf("first %+v, subject %+v: %+v; want strict", first, subject, got)
			}
		}
	}
	set := identityTestSet(t, p, "watch",
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"ldap-privileged"}, Connectors: []string{"cursor"}}})
	if got := set.match(&unknownGroups, profileSubjectVerified, "codex", ""); got.Name != "watch" {
		t.Fatalf("a group assignment of another connector made %+v; want the default", got)
	}
	set = identityTestSet(t, p, "watch",
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"ldap-privileged"}, Users: []string{"2002"}}})
	if got := set.match(&unknownGroups, profileSubjectVerified, "codex", ""); got.Name != "watch" {
		t.Fatalf("a group assignment of a proved other uid made %+v; want the default", got)
	}
}

// When several assignments match, the strictest wins whatever their order
// (owner rule for 1.0.4).
func TestSeveralMatchingAssignmentsTheStrictestWins(t *testing.T) {
	p := identityTestPlatforms[0]
	subject := identityTestSubject(p, p.providers[1], stateProven, true)
	for _, order := range [][]config.ProfileAssignment{
		{{Profile: "watch", Match: config.ProfileMatch{Users: []string{"alice"}}}, {Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}}},
		{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}}, {Profile: "watch", Match: config.ProfileMatch{Users: []string{"alice"}}}},
		{{Profile: "tooling", Match: config.ProfileMatch{Connectors: []string{"codex"}}}, {Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}}},
	} {
		set := identityTestSet(t, p, "watch", order...)
		got := set.match(&subject, profileSubjectVerified, "codex", "")
		if got.Name != "strict" || got.Match != profileMatchGroup {
			t.Fatalf("assignments %+v: %+v; want strict as group", order, got)
		}
	}
}

// The last profile proven for an exact incarnation is a candidate while a
// fact is unproven; another incarnation of the same uid (a recreated
// account) never inherits it.
func TestLastProvenProfileIsKeyedByTheWholeIncarnation(t *testing.T) {
	p := identityTestPlatforms[0]
	set := identityTestSet(t, p, "watch",
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}},
		config.ProfileAssignment{Profile: "tooling", Match: config.ProfileMatch{Groups: []string{"tools"}}})
	proven := identityTestSubject(p, p.providers[1], stateProven, false)
	proven.UPN = "alice@corp.example"
	if got := set.match(&proven, profileSubjectVerified, "codex", ""); got.Name != "strict" {
		t.Fatalf("proven UPN: %+v; want strict", got)
	}
	// Groups unknown now, and the UPN is not given this pass: the UPN
	// entry may apply, and the incarnation was proven strict.
	later := identityTestSubject(p, p.providers[1], stateGroupsUnknown, false)
	later.upnUnproven = true
	if got := set.match(&later, profileSubjectVerified, "codex", ""); got.Name != "strict" || !slices.Contains(got.Candidates, "strict") {
		t.Fatalf("unproven UPN and groups: %+v; want strict", got)
	}
	res := resolveIdentity(&later, nil)
	if last, ok := set.provenProfiles.get(res.Incarnation, true); !ok || last != "strict" {
		t.Fatalf("last proven profile %q %v; want strict", last, ok)
	}
	recreated := later
	recreated.accountToken = "S-1-5-21-1-2-3-1777"
	if _, ok := set.provenProfiles.get(resolveIdentity(&recreated, nil).Incarnation, true); ok {
		t.Fatal("a recreated account under the same uid and name inherited the last proven profile")
	}
}

// An unresolved 1.0.3 agents entry anywhere in the list makes the agent
// fact unproven: the strictest profile of those that may apply, the
// default among them, applies in either order (GAP-0337, GAP-0424).
func TestUnresolvedLegacyAgentEntryIsStrictestInEitherOrder(t *testing.T) {
	p := identityTestPlatforms[0]
	const legacy = "agt-00000000000000aa"
	subject := identityTestSubject(p, p.providers[0], stateProven, false)
	unresolved := func(entry string) bool { return entry == legacy }
	for _, legacyFirst := range []bool{true, false} {
		legacyAssignment := config.ProfileAssignment{Profile: "watch", Match: config.ProfileMatch{Agents: []string{legacy}}}
		general := config.ProfileAssignment{Profile: "watch", Match: config.ProfileMatch{Connectors: []string{"codex"}}}
		assignments := []config.ProfileAssignment{general, legacyAssignment}
		if legacyFirst {
			assignments = []config.ProfileAssignment{legacyAssignment, general}
		}
		set := identityTestSet(t, p, "strict", assignments...)
		got := set.selectProfile(&subject, resolveIdentity(&subject, unresolved), profileSubjectVerified, "codex", "agt-00000000000000bb")
		if got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed {
			t.Fatalf("legacyFirst=%v: %+v; want the strict default", legacyFirst, got)
		}
	}
}

// Privacy: the account a meet applies to sees it as the strictest
// combination, never the names of its members (one may be the profile of a
// group it is not proven to be in, or another account's).
func TestMeetNamesNoMemberToTheAccount(t *testing.T) {
	p := identityTestPlatforms[0]
	cfg := &config.Config{}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict":  {Mode: "action", BlockAt: "LOW", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
		"default": {Mode: "action", BlockAt: "HIGH"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}, Users: []string{"bob@corp.example"}}},
	}
	cfg.Guardrail.DefaultProfile = "default"
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	subject := identityTestSubject(p, p.providers[1], stateUnknown, true)
	got := set.match(&subject, profileSubjectVerified, "codex", "")
	label := profileUserLabel(got.Name)
	if !config.IsProfileMeet(got.Name) || label != profileMeetLabel || strings.Contains(label, "default") || strings.Contains(label, "bob") ||
		strings.Contains(label, p.group) || strings.Contains(label, got.Name) {
		t.Fatalf("decision %+v shown as %q; want the strictest combination, naming no member", got, label)
	}
	if profileUserLabel("strict") != "strict" {
		t.Fatal("a single profile keeps its own name")
	}
}
