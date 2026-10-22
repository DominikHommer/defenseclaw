// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Identity resolution and the one profile selection rule.
//
// resolveIdentity says, for one request, which account incarnation it comes
// from and how each fact that can decide its guardrail profile is known:
// the account (which account holds the verified uid or SID, its name,
// domain and UPN), its groups, and the request agent's ownership of a
// pre-1.0.4 agents entry. Each fact is proven, stale, unknown or failed
// (proofStatus). selectProfile then applies one rule, with no exception:
//
//   - Every assignment is evaluated against the facts as yes, no or maybe:
//     maybe when a fact it needs is not proven in this pass.
//   - When every fact is proven, the profiles of the assignments that match
//     are the candidates, or default_profile when none does, and the
//     strictest of them applies, whatever their order; of profiles that
//     enforce different rules, the first listed (provenProfileOf).
//   - When any fact is not proven (absent, incomplete, timed out, a provider
//     error anywhere in the NSS, SSSD, LDAP, winbind or Windows token chain,
//     an ambiguous name or uid, an unproven 1.0.3 agents entry), the
//     candidates are the profile the proven matches decide, every profile
//     that could match the account (maybe), default_profile and the last
//     profile proven for this exact incarnation. A profile that enforces at
//     least what each of them enforces applies (profileCovers); when none
//     does, the request is refused wherever its surface can block it, and
//     Name is the strictest of them by hook mode and block_at for the rest.
//     It never resolves to a weaker default.
//
// This replaces the earlier special cases (matchWithFailedLookup,
// matchWithUnknownGroups, matchWithUnconfirmedGroups, the unproven-candidate
// and shared-uid refusals, and the legacy agent layering of matchAgent).

// proofStatus is how one identity fact is known in this pass.
type proofStatus string

const (
	// proofProven: the fact was proven in this pass, or by facts the
	// identity cache holds within their TTL (hooks and explain apply the
	// same cached facts during an outage).
	proofProven proofStatus = "proven"
	// proofStale: the fact is a proof of an earlier pass that this pass
	// could not repeat, past the TTL the cache trusts it for. The cache
	// drops such facts, so a request sees them as unknown; explain and the
	// refusal text name the state.
	proofStale proofStatus = "stale"
	// proofUnknown: the fact is not known (a lookup that has not answered,
	// timed out, or left the fact out).
	proofUnknown proofStatus = "unknown"
	// proofFailed: the lookup answered, and its answer disproves a single
	// account (a uid more than one account holds, a name that does not
	// match).
	proofFailed proofStatus = "failed"
)

// identityIncarnation names one account incarnation: the verified uid or
// SID, the account that holds it, and a token that changes when the account
// is recreated under the same uid and name (the SSSD or AD account SID, a
// macOS account's local node record; a Windows SID is its own token).
// Caches of proven decisions are keyed by the whole incarnation (key),
// never by a bare uid or a spelling. An account no such token names (a
// local Linux account, an LDAP or winbind account, a macOS directory
// account with no local record) has no key: its uid, name and domain are
// the same for an account deleted and created again, so nothing proven is
// kept for it. The UPN is a fact of the incarnation, not part of its key.
type identityIncarnation struct {
	Kind, ID          string
	Name, Domain, UPN string
	Token             string
}

// key is the incarnation's cache key, or "" when the account that holds
// the ID is not proven.
func (i identityIncarnation) key() string {
	if i.ID == "" || i.Token == "" {
		return ""
	}
	return strings.Join([]string{i.Kind, strings.ToLower(i.ID), strings.ToLower(i.Token),
		strings.ToLower(i.Name), strings.ToLower(i.Domain)}, "\x00")
}

// identityResolution is resolveIdentity's answer for one request.
type identityResolution struct {
	Incarnation identityIncarnation
	Account     proofStatus
	// UPN is the account's UPN, which a guardian-backed gateway takes from
	// the guardian's identity record: unknown while that record has not
	// given it (awaitingSpoolUPN).
	UPN    proofStatus
	Groups proofStatus
	Agent  proofStatus
	// unconfirmedGroups are the gids whose names no NSS group service could
	// give or prove absent; the account is in them (initgroups proved it).
	unconfirmedGroups []string
	// agentUnresolved reports the agents entries (lower case) that may be
	// the request agent's 1.0.3 identity; nil when none may.
	agentUnresolved func(entry string) bool
	// agentOwned reports the agents entries (lower case) the 1.0.3 bridge
	// proves are the request agent's own 1.0.3 identity
	// (profileAgentBridge): they match as the agent's identity does.
	agentOwned func(entry string) bool
}

// proven reports whether every fact is proven.
func (r identityResolution) proven() bool {
	return r.Account == proofProven && r.UPN == proofProven && r.Groups == proofProven && r.Agent == proofProven
}

// unprovenFacts names the facts that are not proven, for explain.
func (r identityResolution) unprovenFacts() []string {
	var out []string
	for _, fact := range []struct {
		name   string
		status proofStatus
	}{{"account", r.Account}, {"upn", r.UPN}, {"groups", r.Groups}, {"agent", r.Agent}} {
		if fact.status != proofProven {
			out = append(out, fact.name+":"+string(fact.status))
		}
	}
	return out
}

// resolveIdentity computes the identity facts of a verified subject and
// their proof status. agentUnresolved is the bridge's answer for the
// request agent (profileAgent). An unverified request (no subject) names no
// account and no facts; only connector-only assignments can select it.
func resolveIdentity(subject *profileSubject, agentUnresolved func(string) bool) identityResolution {
	res := identityResolution{Account: proofProven, UPN: proofProven, Groups: proofProven, Agent: proofProven, agentUnresolved: agentUnresolved}
	if agentUnresolved != nil {
		res.Agent = proofUnknown
	}
	if subject == nil {
		return res
	}
	res.Incarnation = identityIncarnation{Kind: subject.IDKind, ID: subject.UserID}
	switch {
	case subject.LookupFailed:
		// The account that holds the uid, its names and its groups are not
		// known: the lookup failed, ran over its budget, found the uid held
		// by more than one account, or lacked a proof (an uncheckable
		// directory, an offline domain behind a live responder).
		res.Account, res.UPN, res.Groups = proofUnknown, proofUnknown, proofUnknown
		if subject.LookupError != "" && strings.Contains(subject.LookupError, "more than one account") {
			res.Account = proofFailed
		}
	default:
		if subject.upnUnproven {
			res.UPN = proofUnknown
		}
		if subject.GroupsUnknown {
			res.Groups = proofUnknown
		} else if len(subject.unconfirmedGroups) > 0 {
			res.Groups = proofUnknown
			res.unconfirmedGroups = subject.unconfirmedGroups
		}
	}
	if res.Account == proofProven {
		res.Incarnation.Name, res.Incarnation.Domain, res.Incarnation.UPN = subject.UserName, subject.Domain, subject.UPN
		res.Incarnation.Token = subject.accountToken
		if res.Incarnation.Token == "" && subject.IDKind == useridentity.KindWindowsSID {
			res.Incarnation.Token = subject.UserID
		}
	}
	return res
}

// matchState is how an assignment holds for a request.
type matchState int

const (
	matchNo matchState = iota
	matchMaybe
	matchYes
)

// assignmentState evaluates m for the request: yes when the proven facts
// satisfy every key, no when a proven fact rules a key out, and maybe when
// a key depends on a fact that is not proven. reason and group are the
// match reason of a yes, as assignmentMatches gives them.
func (set *guardrailProfileSet) assignmentState(m config.ProfileMatch, subject *profileSubject, res identityResolution,
	verified bool, connectorName, agent string) (state matchState, reason, group string) {
	if !verified || subject == nil {
		if reason, group, ok := assignmentMatches(m, subject, &subjectGroups{}, false, connectorName, agent); ok {
			return matchYes, reason, group
		}
		return matchNo, "", ""
	}
	if m.Empty() {
		return matchNo, "", ""
	}
	state = matchYes
	lower := func(next matchState) {
		if next < state {
			state = next
		}
	}
	if len(m.Connectors) > 0 {
		if connectorName == "" || !anyMatches(m.Connectors, func(v string) bool { return config.NormalizeConnectorName(v) == connectorName }) {
			return matchNo, "", ""
		}
		reason = profileMatchConnector
	}
	if len(m.Groups) > 0 {
		groupState, matched := set.groupsState(m.Groups, subject, res)
		if groupState == matchNo {
			return matchNo, "", ""
		}
		lower(groupState)
		if groupState == matchYes {
			reason, group = profileMatchGroup, matched
		}
	}
	if len(m.Users) > 0 {
		userState := matchNo
		for _, entry := range m.Users {
			entry = strings.TrimSpace(entry)
			switch {
			case useridentity.KindForID(entry) != "":
				// A uid or SID entry compares with the kernel-verified ID,
				// which is always proven.
				if useridentity.EqualFold(entry, subject.UserID) {
					userState = matchYes
				}
			case res.Account == proofProven:
				if userEntryMatches(subject, entry) {
					userState = matchYes
				} else if res.UPN != proofProven && strings.ContainsAny(entry, `@\`) {
					// A UPN or DOMAIN\name entry may name the account
					// through the UPN the guardian has not given yet.
					userState = max(userState, matchMaybe)
				}
			default:
				// Any name, UPN or principal may be the unproven account's.
				userState = max(userState, matchMaybe)
			}
			if userState == matchYes {
				break
			}
		}
		if userState == matchNo {
			return matchNo, "", ""
		}
		lower(userState)
		if userState == matchYes {
			reason, group = profileMatchUser, ""
		}
	}
	if len(m.Agents) > 0 {
		agentState := matchNo
		if anyMatches(m.Agents, func(v string) bool {
			return agentEntryMatches(v, agent) || (res.agentOwned != nil && res.agentOwned(strings.ToLower(strings.TrimSpace(v))))
		}) {
			agentState = matchYes
		} else if res.agentUnresolved != nil &&
			anyMatches(m.Agents, func(v string) bool { return res.agentUnresolved(strings.ToLower(strings.TrimSpace(v))) }) {
			agentState = matchMaybe
		}
		if agentState == matchNo {
			return matchNo, "", ""
		}
		lower(agentState)
		if agentState == matchYes {
			reason, group = profileMatchAgent, ""
		}
	}
	if state != matchYes {
		return state, "", ""
	}
	return matchYes, reason, group
}

// groupsState evaluates a groups key. Proven groups decide it. Unknown
// groups make every entry a maybe. With some gids unconfirmed, a proven
// group still matches; otherwise a numeric entry may name an unconfirmed
// gid without a name, and any group name may be the name of one.
func (set *guardrailProfileSet) groupsState(entries []string, subject *profileSubject, res identityResolution) (matchState, string) {
	proven := subject.Groups
	if len(res.unconfirmedGroups) > 0 {
		proven = slices.DeleteFunc(slices.Clone(subject.Groups), func(group string) bool {
			return slices.Contains(res.unconfirmedGroups, strings.TrimSpace(group))
		})
	}
	if res.Groups == proofProven || len(res.unconfirmedGroups) > 0 {
		groups := &subjectGroups{list: proven, sids: set.groupSIDs}
		for _, want := range entries {
			if groups.has(want) {
				return matchYes, strings.TrimSpace(want)
			}
		}
		if res.Groups == proofProven {
			return matchNo, ""
		}
	}
	if len(res.unconfirmedGroups) > 0 {
		for _, want := range entries {
			want = strings.TrimSpace(want)
			if want == "" {
				continue
			}
			if strings.Trim(want, "0123456789") == "" {
				if slices.Contains(res.unconfirmedGroups, want) {
					return matchMaybe, ""
				}
				continue
			}
			return matchMaybe, ""
		}
		return matchNo, ""
	}
	if slices.ContainsFunc(entries, func(want string) bool { return strings.TrimSpace(want) != "" }) {
		return matchMaybe, ""
	}
	return matchNo, ""
}

// selectProfile is the one profile selection rule (see the top of this
// file) for subject, verified by source, on connectorName for agent.
func (set *guardrailProfileSet) selectProfile(subject *profileSubject, res identityResolution, source, connectorName, agent string) profileDecision {
	verified := subject != nil && source != ""
	type hit struct {
		index         int
		profile       string
		reason, group string
	}
	var yes []hit
	var maybe []string
	for i, assignment := range set.assignments {
		state, reason, group := set.assignmentState(assignment.Match, subject, res, verified, connectorName, agent)
		switch state {
		case matchYes:
			yes = append(yes, hit{index: i + 1, profile: strings.TrimSpace(assignment.Profile), reason: reason, group: group})
		case matchMaybe:
			maybe = append(maybe, strings.TrimSpace(assignment.Profile))
		}
	}
	definite := func(name string) (profileDecision, bool) {
		for _, h := range yes {
			if h.profile == name {
				decision := set.decision(h.profile, h.reason, h.group, source)
				decision.Assignment = h.index
				return decision, true
			}
		}
		return profileDecision{}, false
	}
	var matched []string
	for _, h := range yes {
		matched = append(matched, h.profile)
	}
	// The proven matches decide one profile: the strictest of them, or of
	// profiles that enforce different rules the first one listed.
	candidates := []string{set.defaultProfile}
	if len(matched) > 0 {
		candidates = []string{set.provenProfileOf(matched, connectorName)}
	}
	if !verified || len(maybe) == 0 {
		// No assignment depends on a fact that is not proven: the facts
		// decide (provenProfileOf).
		name := candidates[0]
		decision, ok := definite(name)
		if !ok {
			reason := profileMatchDefault
			switch {
			case !verified:
				reason = profileMatchDefaultUnverified
			case subject.LookupFailed || subject.GroupsUnknown:
				// The default, with facts this pass did not prove: no
				// assignment depends on them, but the lookup failed.
				reason = profileMatchDefaultLookupFailed
			}
			decision = set.decision(set.defaultProfile, reason, "", source)
		}
		if verified && res.proven() {
			set.provenProfiles.note(res.Incarnation, decision.Name)
		}
		return decision
	}
	// An assignment may or may not apply: the strictest of every profile
	// that could match, default_profile (the configured fallback) and the
	// last profile proven for this incarnation.
	// default_profile is tried first, so an outage reports the configured
	// fallback when it is as strict as any other.
	candidates = append(append([]string{set.defaultProfile}, candidates...), maybe...)
	if last, ok := set.provenProfiles.get(res.Incarnation, res.Account == proofProven); ok {
		candidates = append(candidates, last)
	}
	candidates = compactProfiles(candidates)
	name, covers := set.strictestOf(candidates, connectorName)
	decision, ok := definite(name)
	if !ok || !covers {
		// A profile the proven facts select keeps its reason when it is
		// the strictest; any other is the unproven fallback.
		decision = set.decision(name, profileMatchDefaultLookupFailed, "", source)
	}
	decision.Unproven = res.unprovenFacts()
	decision.Candidates = candidates
	if !covers {
		decision.Refused = set.unprovenRefusalReason(subject, res, connectorName)
	}
	return decision
}

// provenProfileOf is the profile of the assignments that match on proven
// facts (matched, in assignment order): the strictest, whatever their order,
// when one enforces at least what each of the others does (strictestOf).
// Profiles that enforce different rules (a rule pack, a sandbox section, a
// HILT) have no strictest one, and a choice by hook mode and block_at would
// drop what the other enforces: the first listed of those no other one
// covers applies, as every release before 1.0.4 chose (first match). A
// profile another one covers never applies in its place.
func (set *guardrailProfileSet) provenProfileOf(matched []string, connectorName string) string {
	if name, covers := set.strictestOf(matched, connectorName); covers {
		return name
	}
	connectors := profileCoverConnectors(connectorName)
	for _, candidate := range matched {
		if !slices.ContainsFunc(matched, func(other string) bool {
			return set.profileCovers(other, candidate, connectors) && !set.profileCovers(candidate, other, connectors)
		}) {
			return candidate
		}
	}
	return matched[0]
}

// compactProfiles drops repeated names, keeping the first.
func compactProfiles(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// strictestOf picks the strictest of candidates for connectorName: the
// first that enforces at least what each of the others does
// (profileCovers), with covers true; when none does, the strictest by hook
// mode and block_at (profileStricter, the first of equals), with covers
// false.
func (set *guardrailProfileSet) strictestOf(candidates []string, connectorName string) (name string, covers bool) {
	if len(candidates) == 0 {
		return set.defaultProfile, true
	}
	connectors := profileCoverConnectors(connectorName)
	for _, candidate := range candidates {
		if !slices.ContainsFunc(candidates, func(other string) bool { return !set.profileCovers(candidate, other, connectors) }) {
			return candidate, true
		}
	}
	strictest := candidates[0]
	for _, candidate := range candidates[1:] {
		if set.profileStricter(candidate, strictest, connectorName) {
			strictest = candidate
		}
	}
	return strictest, false
}

// unprovenRefusalReason is what a refused request tells the agent and its
// user: which fact is not proven, and the command that explains the
// decision on this host.
func (set *guardrailProfileSet) unprovenRefusalReason(subject *profileSubject, res identityResolution, connectorName string) string {
	var why, then []string
	step := func(text string) {
		if !slices.Contains(then, text) {
			then = append(then, text)
		}
	}
	switch res.Account {
	case proofFailed:
		why = append(why, "more than one account holds this account's uid")
		step("ask your administrator to give each account its own uid")
	case proofUnknown:
		why = append(why, "the directory has not confirmed which account this is")
		step("try again after the directory recovers")
	case proofStale:
		why = append(why, "the directory cannot confirm this account now")
		step("try again after the directory recovers")
	}
	if res.Account == proofProven {
		// The account's own facts this pass did not prove; an unproven
		// account leaves them unproven too, and its reason covers them.
		if res.Groups != proofProven {
			why = append(why, "directory group membership is unconfirmed")
			step("try again after the directory recovers")
		}
		if res.UPN != proofProven {
			why = append(why, "the DefenseClaw guardian has not recorded this account's UPN yet")
			step("try again after the guardian writes this account's identity record")
		}
	}
	if res.Agent != proofProven {
		why = append(why, "a guardrail profile assignment names an agent identity from before the upgrade that cannot be matched to this account")
		step("ask your administrator to replace the entry with the agent identity `defenseclaw agent identities` shows now")
	}
	if len(why) == 0 {
		// Not reached: a refusal needs an unproven fact. Never an empty
		// reason.
		why = append(why, "an identity fact the guardrail profile depends on is not confirmed")
	}
	text := "DefenseClaw refused this request: " + strings.Join(why, "; ") +
		", and the guardrail profiles that may apply enforce different rules"
	if len(then) > 0 {
		text += "; " + strings.Join(then, "; ")
	}
	return text + "; run `" + set.profileExplainCommand(subject, connectorName) + "` to see the decision"
}

// profileExplainCommand is the installed command that explains the profile
// of subject on this host.
func (set *guardrailProfileSet) profileExplainCommand(subject *profileSubject, connectorName string) string {
	if subject == nil || subject.UserID != strings.TrimSpace(subject.UserID) || useridentity.KindForID(subject.UserID) == "" {
		return "defenseclaw guardrail profile list"
	}
	command := "defenseclaw guardrail profile explain --user " + subject.UserID
	if set.base != nil && set.base.StandaloneEnterprise() {
		switch runtime.GOOS {
		case "linux":
			command = "sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux profile-explain --user " + subject.UserID
		case "darwin":
			command = "sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise macos profile-explain --user " + subject.UserID
		case "windows":
			command = `& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe' enterprise windows profile-explain --user ` + subject.UserID
		}
	}
	if profileCommandToken(connectorName) {
		command += " --connector " + connectorName
	}
	return command
}

// profileCommandToken is a shell-safe connector argument in a diagnostic
// command. The subject ID is validated as a numeric uid or a SID.
func profileCommandToken(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// provenProfileStore holds the last profile a fully proven decision gave
// each account incarnation (identityIncarnation.key), for the unproven
// rule: an outage never selects a weaker profile than the one the same
// account was last proven to have. It keeps one incarnation per uid or SID:
// once another account is proven to hold it (another token, or one with no
// token), the former one's profile is forgotten, so it never reaches the
// new account, nor the former one's block message. It is per profile set,
// so a configuration change starts it empty, and bounded.
type provenProfileStore struct {
	mu    sync.Mutex
	byKey map[string]provenProfile
	// holders maps a uid or SID (provenProfileHolder) to the key of the
	// incarnation whose profile is kept for it.
	holders map[string]string
	order   []string
}

type provenProfile struct {
	profile, holder string
}

// provenProfileStoreMax bounds a provenProfileStore.
const provenProfileStoreMax = 4096

func provenProfileHolder(inc identityIncarnation) string {
	return inc.Kind + "\x00" + strings.ToLower(inc.ID)
}

// note keeps profile for inc, an incarnation a fully proven decision
// resolved.
func (s *provenProfileStore) note(inc identityIncarnation, profile string) {
	if s == nil || inc.ID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := inc.key()
	s.forgetOtherHolderLocked(inc, key)
	if key == "" {
		return
	}
	if s.byKey == nil {
		s.byKey, s.holders = map[string]provenProfile{}, map[string]string{}
	}
	if _, ok := s.byKey[key]; !ok {
		if len(s.order) >= provenProfileStoreMax {
			s.forgetLocked(s.order[0])
		}
		s.order = append(s.order, key)
	}
	holder := provenProfileHolder(inc)
	s.byKey[key] = provenProfile{profile: profile, holder: holder}
	s.holders[holder] = key
}

// get returns the profile kept for inc. accountProven reports that this
// pass proved which account holds inc's ID: when that is another
// incarnation than the one kept, the kept one is forgotten.
func (s *provenProfileStore) get(inc identityIncarnation, accountProven bool) (string, bool) {
	if s == nil || inc.ID == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := inc.key()
	if accountProven {
		s.forgetOtherHolderLocked(inc, key)
	}
	if key == "" {
		return "", false
	}
	kept, ok := s.byKey[key]
	return kept.profile, ok
}

// forgetOtherHolderLocked forgets the profile kept for inc's ID when it was
// kept for another incarnation than key (a recreated account, or one that
// no token names). s.mu is held.
func (s *provenProfileStore) forgetOtherHolderLocked(inc identityIncarnation, key string) {
	if previous, ok := s.holders[provenProfileHolder(inc)]; ok && previous != key {
		s.forgetLocked(previous)
	}
}

// forgetLocked drops the profile kept under key. s.mu is held.
func (s *provenProfileStore) forgetLocked(key string) {
	kept, ok := s.byKey[key]
	if !ok {
		return
	}
	delete(s.byKey, key)
	if s.holders[kept.holder] == key {
		delete(s.holders, kept.holder)
	}
	s.order = slices.DeleteFunc(s.order, func(k string) bool { return k == key })
}

// profileCoverConnectors are the connectors the decisions of a request of
// connectorName read: its own, and the global settings for a decision
// taken without one.
func profileCoverConnectors(connectorName string) []string {
	if connectorName == "" {
		return []string{""}
	}
	return []string{connectorName, ""}
}

// profileCovers reports whether profile a enforces at least what profile b
// enforces for a request decided for connectors: the same sandbox section,
// and wherever b blocks (action, by the hook mode or by the inspect and
// proxy mode) a blocks too, with b's rule pack and rules, from a block
// level at or below b's, and with a HILT that asks wherever b's asks. Where
// b only observes it blocks nothing, so a's guardrail settings there do not
// matter. A name that is not a profile is the base configuration. alert_at
// and block_message enforce nothing and are not compared.
func (set *guardrailProfileSet) profileCovers(a, b string, connectors []string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == b {
		return true
	}
	ca, cb := set.profileConfig(a), set.profileConfig(b)
	if ca == nil || cb == nil || !reflect.DeepEqual(set.profileSandbox(a), set.profileSandbox(b)) {
		return false
	}
	for _, name := range connectors {
		hookB, inspectB := hookModeForConfig(cb, name) == "action", inspectMode(cb, name) == "action"
		if !hookB && !inspectB {
			continue
		}
		if (hookB && hookModeForConfig(ca, name) != "action") || (inspectB && inspectMode(ca, name) != "action") {
			return false
		}
		if effectiveRulePackKey(ca, name) != effectiveRulePackKey(cb, name) ||
			!reflect.DeepEqual(ca.Guardrail.EffectiveRulePackRef(name), cb.Guardrail.EffectiveRulePackRef(name)) {
			return false
		}
		blockA, _ := guardrailThresholdRanks(resolveThresholds(ca, name))
		blockB, _ := guardrailThresholdRanks(resolveThresholds(cb, name))
		proxyA, _ := guardrailThresholdRanks(resolveGuardrailThresholds(&ca.Guardrail, name))
		proxyB, _ := guardrailThresholdRanks(resolveGuardrailThresholds(&cb.Guardrail, name))
		if blockA > blockB || proxyA > proxyB {
			return false
		}
		if !hiltCovers(hiltEnabledForConfig(ca, name), hiltMinRankForConfig(ca, name), hiltEnabledForConfig(cb, name), hiltMinRankForConfig(cb, name)) ||
			!hiltCovers(hiltEnabled(&ca.Guardrail, name), hiltMinRank(&ca.Guardrail, name), hiltEnabled(&cb.Guardrail, name), hiltMinRank(&cb.Guardrail, name)) {
			return false
		}
	}
	return true
}

// hiltCovers reports whether a HILT (enabledA, from severity rank minA)
// asks wherever another one asks. A confirm stands only below the block
// level, so asking more never allows more.
func hiltCovers(enabledA bool, minA int, enabledB bool, minB int) bool {
	return !enabledB || (enabledA && minA <= minB)
}

// profileSandbox is the sandbox section of profile name; nil for the base
// configuration.
func (set *guardrailProfileSet) profileSandbox(name string) *config.OpenShellAdminConfig {
	if set.base == nil {
		return nil
	}
	return set.base.Guardrail.Profiles[name].Sandbox
}

// profileStricter orders profiles that do not cover each other: a blocks
// (action) where b only observes, or both block and a blocks from a lower
// severity (block_at). A name that is not a profile is the base
// configuration.
func (set *guardrailProfileSet) profileStricter(a, b, connectorName string) bool {
	ca, cb := set.profileConfig(a), set.profileConfig(b)
	modeA, modeB := hookModeForConfig(ca, connectorName), hookModeForConfig(cb, connectorName)
	if modeA != modeB {
		return modeA == "action"
	}
	rankA, rankB := blockAtRank(ca, connectorName), blockAtRank(cb, connectorName)
	return rankA > 0 && rankB > 0 && rankA > rankB
}

// profileConfig is the configuration a decision for profile name applies.
func (set *guardrailProfileSet) profileConfig(name string) *config.Config {
	if derived, ok := set.profiles[strings.TrimSpace(name)]; ok && derived.Config != nil {
		return derived.Config
	}
	return set.base
}

// blockAtRank ranks cfg's block_at for connectorName: 4 for LOW (blocks
// most) to 1 for CRITICAL, 0 when unset (the rule pack decides).
func blockAtRank(cfg *config.Config, connectorName string) int {
	if cfg == nil {
		return 0
	}
	switch cfg.Guardrail.EffectiveBlockAt(connectorName) {
	case "LOW":
		return 4
	case "MEDIUM":
		return 3
	case "HIGH":
		return 2
	case "CRITICAL":
		return 1
	}
	return 0
}

// unprovenRefusalNote is explain's account of a refused decision.
func unprovenRefusalNote(decision profileDecision) string {
	return fmt.Sprintf("requests from this account are refused where they can be blocked: %s are not proven, and none of the profiles "+
		"that may apply (%s) enforces what each of the others does", strings.Join(decision.Unproven, ", "), strings.Join(decision.Candidates, ", "))
}
