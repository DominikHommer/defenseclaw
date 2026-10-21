// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// profileAgentBridge links the agent identity a qualified account's agent
// has now to the legacy identity (1.0.0 to 1.0.3, keyed without the
// account's domain) a profile assignment may still name. The agent ledger
// links them: the legacy identity's record names the account that held the
// uid when 1.0.3 last saw the agent, and that account's identity now is the
// one a request carries. A namesake from another domain that is given the
// uid after the upgrade derives another identity and is not linked
// (GAP-1055).
//
// 1.0.3 kept one record for every domain's namesake of a uid and wrote the
// last one's name over the earlier one's, so the name alone does not prove
// whose agent the assignment was written for. When the ledger holds another
// domain's namesake of the same uid on the machine, the legacy entry is
// linked to neither account, and it stays unresolved for both. So does an
// entry that is the agent's own legacy identity (the hook path derives it
// with the request's identity) while no record proves which account it was
// written for: the ledger cannot be read, 1.0.3 pruned the record of an
// agent idle for the retention window (a prune now keeps the records the
// bridge reads, inventory.retireLegacyAgentIdentities), or 1.0.3 recorded
// the account under another spelling (alice or CORP\alice, now
// alice@corp.example), which no record proves is the same account. An
// assignment with an unresolved entry never resolves to a weaker profile
// than one that may apply (matchAgent). Remove with
// agentidentity.LegacyAgentID.
type profileAgentBridge struct {
	once sync.Once
	// entries are the assignments' agents entries, lower-cased.
	entries map[string]bool
	mu      sync.Mutex
	// legacy maps an identity to the legacy entry linked to it; nil until
	// the ledger answered.
	legacy map[string]string
	// ambiguous maps an identity to the legacy entries it may hold but
	// does not prove (the namesakes' records).
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
// hold may or may not apply. The request then gets the strictest of the
// default profile, the profile of each such assignment and the profile it
// matches otherwise (profileStricter), reported as default_lookup_failed:
// unproven ownership never resolves to a weaker profile, whatever
// default_profile says, and a later assignment never applies in its place.
func (set *guardrailProfileSet) matchAgent(subject *profileSubject, source, connectorName, agent string, legacy profileAgentLegacy) profileDecision {
	matched, unresolved := set.profileAgent(agent, legacy)
	decision := set.match(subject, source, connectorName, matched)
	if unresolved == nil || subject == nil || source == "" {
		return decision
	}
	earlier := set.assignments
	if decision.Assignment > 0 && decision.Assignment <= len(earlier) {
		earlier = earlier[:decision.Assignment-1]
	}
	var candidates []string
	for _, assignment := range earlier {
		if set.unresolvedAgentMatch(assignment.Match, subject, connectorName, unresolved) {
			candidates = append(candidates, strings.TrimSpace(assignment.Profile))
		}
	}
	if len(candidates) == 0 {
		return decision
	}
	// The outage default, unless a profile that may apply enforces more.
	strictest := set.defaultProfile
	for _, name := range append(candidates, decision.Name) {
		if set.profileStricter(name, strictest, connectorName) {
			strictest = name
		}
	}
	return set.decision(strictest, profileMatchDefaultLookupFailed, "", source)
}

// profileStricter reports whether profile a enforces more than profile b
// for a request of connectorName: a blocks (action) where b only observes,
// or both block and a blocks from a lower severity (block_at). A name that
// is not a profile is the base configuration. Rule packs and their rules
// are not compared: of two profiles that block alike, the one already
// chosen stays.
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
	_, _, ok := assignmentMatches(others, subject, &subjectGroups{list: subject.Groups, sids: set.groupSIDs}, true, connectorName, "")
	return ok
}

// profileAgent is the agents entry the request's agent identity agent is
// matched as: agent, or, when no assignment names agent, the legacy
// identity an assignment names for the same account. unresolved, when not
// nil, reports the entries that may be agent's legacy identity without the
// ledger proving it.
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
	if len(bridge.entries) == 0 || bridge.entries[strings.ToLower(agent)] {
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
	linked, unresolved := bridge.legacyOf(strings.ToLower(agent), own, known)
	if linked != "" {
		return linked, nil
	}
	return agent, unresolved
}

// legacyOf is profileAgent's ledger side; own is agent's legacy identity
// when known.
func (b *profileAgentBridge) legacyOf(agent, own string, known bool) (string, func(string) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now := time.Now(); !now.Before(b.readAt) {
		if ledger, ok := b.readLedger(); ok {
			b.legacy, b.ambiguous, b.derived, b.readAt = ledger.legacy, ledger.ambiguous, ledger.derived, now.Add(profileAgentBridgeRefresh)
		} else {
			b.readAt = now.Add(profileAgentBridgeRetry)
			if b.legacy == nil && !b.noted[""] {
				b.note("")
				fmt.Fprintf(os.Stderr, "[guardrail] the agent ledger cannot be read: an agent that a profile assignment's agents entries may name "+
					"gets the strictest profile that may apply (default_lookup_failed) where such an assignment comes first, until the ledger answers\n")
			}
		}
	}
	if b.legacy == nil {
		if known {
			return "", func(entry string) bool { return entry == own }
		}
		// Any entry may be agent's legacy identity.
		return "", func(entry string) bool { return entry != agent }
	}
	if entries := b.ambiguous[agent]; len(entries) > 0 {
		return "", func(entry string) bool { return entries[entry] }
	}
	if linked := b.legacy[agent]; linked != "" {
		return linked, nil
	}
	if !known {
		recorded, ok := b.derived[agent]
		if !ok {
			// Neither the request nor the ledger says what agent's legacy
			// identity is: any entry may be it.
			return "", func(entry string) bool { return entry != agent }
		}
		own = recorded
	}
	// agent's own legacy identity, which no record links to it.
	if own == "" || !b.entries[own] {
		return "", nil
	}
	if !b.noted["?"+own] {
		b.note("?" + own)
		fmt.Fprintf(os.Stderr, "[guardrail] profile assignment agent %s: no record shows which account 1.0.3 recorded it for; "+
			"agent %s gets the strictest profile that may apply (default_lookup_failed) where it applies until it names the account's current agent identity\n",
			own, agent)
	}
	return "", func(entry string) bool { return entry == own }
}

func (b *profileAgentBridge) note(key string) {
	if b.noted == nil {
		b.noted = map[string]bool{}
	}
	b.noted[key] = true
}

// profileAgentLinks is what the agent ledger says about the assignments'
// legacy entries.
type profileAgentLinks struct {
	// legacy maps an identity to the legacy entry the ledger links to it.
	legacy map[string]string
	// ambiguous maps an identity to the legacy entries it may hold but the
	// ledger does not prove.
	ambiguous map[string]map[string]bool
	// derived maps every recorded identity to its legacy identity.
	derived map[string]string
}

// readLedger links each legacy entry the ledger proves to the identity its
// account has now, and lists the identities that may hold an entry it does
// not prove; false when the ledger cannot be read. It reads every record,
// the ones a prune kept aside included.
func (b *profileAgentBridge) readLedger() (profileAgentLinks, bool) {
	records, ok := profileAgentLedger(inventory.AgentIdentityFilter{Retired: true})
	if !ok {
		return profileAgentLinks{}, false
	}
	links := profileAgentLinks{legacy: map[string]string{}, ambiguous: map[string]map[string]bool{}, derived: map[string]string{}}
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
		if namesakes := profileAgentNamesakes(rec, uidRecords[agentidentity.NormalizeUserID(rec.UserID)]); len(namesakes) > 0 {
			if !b.noted[id] {
				b.note(id)
				fmt.Fprintf(os.Stderr, "[guardrail] profile assignment agent %s: recorded before the upgrade for more than one account of uid %s; "+
					"their agents get the strictest profile that may apply (default_lookup_failed) where it applies until it names the account's current agent identity\n",
					rec.AgentID, rec.UserID)
			}
			for _, account := range append(namesakes, rec.UserName) {
				holder := in
				holder.Account = account
				if current := strings.ToLower(agentidentity.AgentID(holder)); current != "" {
					if links.ambiguous[current] == nil {
						links.ambiguous[current] = map[string]bool{}
					}
					links.ambiguous[current][id] = true
				}
			}
			continue
		}
		links.legacy[strings.ToLower(agentidentity.AgentID(in))] = id
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
