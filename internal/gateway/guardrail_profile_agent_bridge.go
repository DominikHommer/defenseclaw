// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// profileAgentBridge treats the agents entries an assignment wrote for a
// legacy identity (1.0.0 to 1.0.3, keyed without the account's domain) as
// unresolved for every current agent that may have held it. Such an ID
// omits the account's domain, and 1.0.3 kept one record for every domain's
// namesake of a uid and wrote the last one's name over the earlier one's,
// so not even a sole surviving record proves whose agent the assignment was
// written for (GAP-0337). The entry stays unresolved for the account its
// record names and for every namesake of another domain the ledger holds
// under the uid. So does an entry that is the agent's own legacy identity
// (the hook path derives it with the request's identity) while no record
// names it: the ledger cannot be read, 1.0.3 pruned the record of an agent
// idle for the retention window (a prune now keeps the records the bridge
// reads, inventory.retireLegacyAgentIdentities), or 1.0.3 recorded the
// account under another spelling (alice or CORP\alice, now
// alice@corp.example). An assignment with an unresolved entry never
// resolves to a weaker profile than one that may apply, whatever
// default_profile says (matchAgent); only an assignment naming the agent's
// current identity proves it. Remove with agentidentity.LegacyAgentID.
type profileAgentBridge struct {
	once sync.Once
	// entries are the assignments' agents entries, lower-cased.
	entries map[string]bool
	mu      sync.Mutex
	// ambiguous maps an identity to the legacy entries it may hold but
	// the ledger does not prove; nil until the ledger answered.
	ambiguous map[string]map[string]bool
	// derived maps every identity the ledger records to its legacy
	// identity ("" for an account without a domain): explain names an agent
	// by its identity only, so the hook path's derivation is not at hand
	// there.
	derived map[string]string
	// readAt is when the ledger is read again: a namesake recorded later
	// takes a link back.
	readAt time.Time
	// noted holds the ambiguous entries already logged; "" the unreadable
	// ledger.
	noted map[string]bool
}

// profileAgentBridgeRetry is how long a ledger that could not be read is
// left alone; profileAgentBridgeRefresh is how long an answer is kept.
const (
	profileAgentBridgeRetry   = 30 * time.Second
	profileAgentBridgeRefresh = 5 * time.Minute
)

// profileAgentLedger returns the agent ledger's records that filter
// selects, and false when the ledger cannot be read now.
var profileAgentLedger = func(filter inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) {
	store := sharedAgentIdentities.store()
	if store == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	records, _, err := store.ListAgentIdentities(ctx, filter)
	return records, err == nil
}

// profileAgentLegacy returns the legacy identity of a request's agent
// (agentidentity.LegacyAgentID, "" for an account without a domain) and
// true, or false when it is not known.
type profileAgentLegacy func() (legacy string, known bool)

// matchAgent is set.match for a request of the agent identity agent;
// legacy, when not nil, derives agent's legacy identity. When an agents
// entry may be the legacy identity of agent's account but the agent ledger
// does not prove it, an assignment with that entry whose other conditions
// hold may or may not apply. The request then gets, reported as
// default_lookup_failed, a profile that enforces at least what every
// profile that may apply enforces (profileCovers): each such assignment's
// and the one the request matches otherwise. That is the default profile
// when it does, else the first of those that does. Unproven ownership never
// resolves to a weaker profile, whatever default_profile says, and a later
// assignment never applies in its place. When none of them enforces what
// each of the others does (another rule pack, other rules, a HILT that asks
// less or another sandbox section where one of them blocks), no profile is
// safe and the decision is Refused (guardrail_profile_refusal.go); its Name
// is then the strictest of them by hook mode and block_at
// (profileStricter), for what the request's surface cannot refuse.
func (set *guardrailProfileSet) matchAgent(subject *profileSubject, source, connectorName, agent string, legacy profileAgentLegacy) profileDecision {
	matched, unresolved := set.profileAgent(agent, legacy)
	decision := set.match(subject, source, connectorName, matched)
	if unresolved == nil || subject == nil || source == "" || decision.Refused != "" {
		// A refused decision (an unconfirmed group name) is already the
		// strictest answer.
		return decision
	}
	earlier := set.assignments
	if decision.Assignment > 0 && decision.Assignment <= len(earlier) {
		earlier = earlier[:decision.Assignment-1]
	}
	var mayApply []string
	for _, assignment := range earlier {
		if set.unresolvedAgentMatch(assignment.Match, subject, connectorName, unresolved) {
			mayApply = append(mayApply, strings.TrimSpace(assignment.Profile))
		}
	}
	if len(mayApply) == 0 {
		return decision
	}
	mayApply = append(mayApply, decision.Name)
	resolved := set.coverUnproven(mayApply, connectorName, source, profileRefusedReason)
	if resolved.Refused != "" {
		set.agentBridge.noteRefused(agent, mayApply)
	}
	return resolved
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

// profileStricter orders the profiles of a Refused decision (matchAgent),
// for what the request's surface cannot refuse: a blocks (action) where b
// only observes, or both block and a blocks from a lower severity
// (block_at). A name that is not a profile is the base configuration.
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

// unresolvedAgentMatch reports whether m has an unresolved agents entry and
// may hold for subject otherwise.
func (set *guardrailProfileSet) unresolvedAgentMatch(m config.ProfileMatch, subject *profileSubject, connectorName string, unresolved func(string) bool) bool {
	if !anyMatches(m.Agents, func(v string) bool { return unresolved(strings.ToLower(strings.TrimSpace(v))) }) {
		return false
	}
	others := m
	others.Agents = nil
	if others.Empty() {
		return true
	}
	if subject.LookupFailed || subject.GroupsUnknown {
		// Only a connector list can prove it does not apply.
		return len(m.Connectors) == 0 || anyMatches(m.Connectors, func(v string) bool {
			return connectorName != "" && config.NormalizeConnectorName(v) == connectorName
		})
	}
	if _, _, ok := assignmentMatches(others, subject, &subjectGroups{list: provenGroups(subject), sids: set.groupSIDs}, true, connectorName, ""); ok {
		return true
	}
	return set.unconfirmedGroupMayMatch(others, subject, connectorName, "")
}

// profileAgent is what the request's agent identity agent is matched as
// (match's agent argument): agent itself, as no legacy entry is proved to
// be its account's. unresolved, when not nil, reports the entries that may
// be agent's legacy identity; matchAgent then lets no later assignment, one
// naming agent included, apply in place of an earlier one with such an
// entry.
func (set *guardrailProfileSet) profileAgent(agent string, legacy profileAgentLegacy) (matched string, unresolved func(entry string) bool) {
	agent = strings.TrimSpace(agent)
	if set == nil || agent == "" {
		return agent, nil
	}
	bridge := &set.agentBridge
	bridge.once.Do(func() {
		bridge.entries = map[string]bool{}
		for _, assignment := range set.assignments {
			for _, entry := range assignment.Match.Agents {
				if entry = strings.ToLower(strings.TrimSpace(entry)); entry != "" {
					bridge.entries[entry] = true
				}
			}
		}
	})
	if len(bridge.entries) == 0 {
		return agent, nil
	}
	own, known := "", false
	if legacy != nil {
		own, known = legacy()
		own = strings.ToLower(strings.TrimSpace(own))
	}
	if known && (own == "" || !bridge.entries[own]) {
		// No entry is agent's legacy identity.
		return agent, nil
	}
	return agent, bridge.unresolvedLegacy(strings.ToLower(agent), own, known)
}

// unresolvedLegacy is profileAgent's ledger side; own is agent's legacy
// identity when known.
func (b *profileAgentBridge) unresolvedLegacy(agent, own string, known bool) func(string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now := time.Now(); !now.Before(b.readAt) {
		if ledger, ok := b.readLedger(); ok {
			b.ambiguous, b.derived, b.readAt = ledger.ambiguous, ledger.derived, now.Add(profileAgentBridgeRefresh)
		} else {
			b.readAt = now.Add(profileAgentBridgeRetry)
			if b.ambiguous == nil && !b.noted[""] {
				b.note("")
				fmt.Fprintf(os.Stderr, "[guardrail] the agent ledger cannot be read: an agent that a profile assignment's agents entries may name "+
					"gets the strictest profile that may apply (default_lookup_failed) where such an assignment comes first, until the ledger answers\n")
			}
		}
	}
	if b.ambiguous == nil {
		if known {
			return func(entry string) bool { return entry == own }
		}
		// Any entry may be agent's legacy identity.
		return func(entry string) bool { return entry != agent }
	}
	if entries := b.ambiguous[agent]; len(entries) > 0 {
		return func(entry string) bool { return entries[entry] }
	}
	if !known {
		recorded, ok := b.derived[agent]
		if !ok {
			// Neither the request nor the ledger says what agent's legacy
			// identity is: any entry may be it.
			return func(entry string) bool { return entry != agent }
		}
		own = recorded
	}
	// agent's own legacy identity, which no record links to it.
	if own == "" || !b.entries[own] {
		return nil
	}
	if !b.noted["?"+own] {
		b.note("?" + own)
		fmt.Fprintf(os.Stderr, "[guardrail] profile assignment agent %s: no record shows which account 1.0.3 recorded it for; "+
			"agent %s gets the strictest profile that may apply (default_lookup_failed) where it applies until it names the account's current agent identity\n",
			own, agent)
	}
	return func(entry string) bool { return entry == own }
}

func (b *profileAgentBridge) note(key string) {
	if b.noted == nil {
		b.noted = map[string]bool{}
	}
	b.noted[key] = true
}

// noteRefused logs, once per agent, that no profile of those that may apply
// to it is safe (matchAgent).
func (b *profileAgentBridge) noteRefused(agent string, profiles []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := "!" + strings.ToLower(agent)
	if b.noted[key] {
		return
	}
	b.note(key)
	names := make([]string, 0, len(profiles))
	for _, name := range profiles {
		if name == "" {
			name = "(base configuration)"
		}
		names = append(names, name)
	}
	fmt.Fprintf(os.Stderr, "[guardrail] agent %s: a profile assignment's agents entry may be its 1.0.3 identity, and none of the profiles that may apply (%s) "+
		"enforces what each of the others does (rule pack, rules, HILT or sandbox section): its requests are refused where they can be blocked "+
		"(default_lookup_failed) until the agent ledger proves whose entry it is or the entry names the agent's current identity\n",
		agent, strings.Join(names, ", "))
}

// profileAgentLinks is what the agent ledger says about the assignments'
// legacy entries.
type profileAgentLinks struct {
	// ambiguous maps an identity to the legacy entries it may hold but the
	// ledger does not prove.
	ambiguous map[string]map[string]bool
	// derived maps every recorded identity to its legacy identity.
	derived map[string]string
}

// readLedger lists the identities that may hold a legacy entry; false when
// the ledger cannot be read. No record proves an entry's original account,
// a sole surviving one included (GAP-0337). It reads every record, the ones
// a prune kept aside included.
func (b *profileAgentBridge) readLedger() (profileAgentLinks, bool) {
	records, ok := profileAgentLedger(inventory.AgentIdentityFilter{Retired: true})
	if !ok {
		return profileAgentLinks{}, false
	}
	links := profileAgentLinks{ambiguous: map[string]map[string]bool{}, derived: map[string]string{}}
	uidRecords := map[string][]inventory.AgentIdentityRecord{}
	for _, rec := range records {
		uid := agentidentity.NormalizeUserID(rec.UserID)
		uidRecords[uid] = append(uidRecords[uid], rec)
	}
	for _, rec := range records {
		in := agentidentity.Inputs{
			MachineHash: rec.MachineHash, UserID: rec.UserID, Account: rec.UserName,
			Connector: rec.Connector, InstallFP: rec.InstallFP,
		}
		id, legacyID := strings.ToLower(rec.AgentID), strings.ToLower(agentidentity.LegacyAgentID(in))
		if id != legacyID && id == strings.ToLower(agentidentity.AgentID(in)) {
			links.derived[id] = legacyID
		}
		if legacyID == "" || id != legacyID || !b.entries[legacyID] {
			continue
		}
		if !b.noted[id] {
			b.note(id)
			fmt.Fprintf(os.Stderr, "[guardrail] profile assignment agent %s: a pre-1.0.4 ledger row cannot prove its account; "+
				"affected agents get the strictest profile that may apply (default_lookup_failed) until the assignment names the current agent identity\n", rec.AgentID)
		}
		for _, account := range append(profileAgentNamesakes(rec, uidRecords[agentidentity.NormalizeUserID(rec.UserID)]), rec.UserName) {
			holder := in
			holder.Account = account
			if current := strings.ToLower(agentidentity.AgentID(holder)); current != "" {
				if links.ambiguous[current] == nil {
					links.ambiguous[current] = map[string]bool{}
				}
				links.ambiguous[current][id] = true
			}
		}
	}
	return links, true
}

// profileAgentNamesakes returns the names of the accounts of another domain
// with rec's name that held, the ledger's records of rec's uid, records on
// rec's machine: 1.0.3 recorded each of them as rec, under the last one's
// name.
func profileAgentNamesakes(rec inventory.AgentIdentityRecord, held []inventory.AgentIdentityRecord) []string {
	key, domain := agentidentity.AccountKey(rec.UserName), agentidentity.AccountDomain(rec.UserName)
	var out []string
	seen := map[string]bool{}
	for _, other := range held {
		if other.MachineHash != rec.MachineHash ||
			agentidentity.NormalizeUserID(other.UserID) != agentidentity.NormalizeUserID(rec.UserID) ||
			agentidentity.AccountKey(other.UserName) != key {
			continue
		}
		if otherDomain := agentidentity.AccountDomain(other.UserName); otherDomain != "" && otherDomain != domain && !seen[otherDomain] {
			seen[otherDomain] = true
			out = append(out, other.UserName)
		}
	}
	return out
}
