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

// profileAgentBridge treats identities from 1.0.0 to 1.0.3 as unresolved
// when a current agent may have owned them. Those IDs omit the account's
// domain, and 1.0.3 overwrote the only row for namesakes sharing a UID. Even
// a sole surviving row cannot prove who originally owned an assignment. A
// current-ID assignment is authoritative; a legacy one needs an admin rebind.
type profileAgentBridge struct {
	once sync.Once
	// entries are the assignments' agents entries, lower-cased.
	entries map[string]bool
	mu      sync.Mutex
	// ambiguous maps an identity to the legacy entries it may hold but
	// does not prove (the namesakes' records).
	ambiguous map[string]map[string]bool
	// derived maps an identity the ledger records to its legacy identity,
	// when an assignment names that.
	derived map[string]string
	// readAt is when the ledger is read again for newly recorded identities.
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

// matchAgent is set.match for a request of the agent identity agent. When
// an agents entry may be the legacy identity of agent's account but the
// agent ledger cannot prove its original owner, an assignment with that entry whose
// other conditions hold selects the default profile as the outage default
// (default_lookup_failed), as a failed directory lookup does: a later
// assignment never applies in its place.
func (set *guardrailProfileSet) matchAgent(subject *profileSubject, source, connectorName, agent string) profileDecision {
	matched, unresolved := set.profileAgent(agent)
	decision := set.match(subject, source, connectorName, matched)
	if unresolved == nil || subject == nil || source == "" || decision.Match == profileMatchDefaultLookupFailed {
		return decision
	}
	earlier := set.assignments
	if decision.Assignment > 0 && decision.Assignment <= len(earlier) {
		earlier = earlier[:decision.Assignment-1]
	}
	for _, assignment := range earlier {
		if set.unresolvedAgentMatch(assignment.Match, subject, connectorName, unresolved) {
			return set.decision(set.defaultProfile, profileMatchDefaultLookupFailed, "", source)
		}
	}
	return decision
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

// profileAgent keeps the current agent ID for exact assignments and reports
// older entries whose owner is unresolved. A legacy entry never replaces the
// current ID in the matcher.
func (set *guardrailProfileSet) profileAgent(agent string) (matched string, unresolved func(entry string) bool) {
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
	return agent, bridge.unresolvedLegacy(strings.ToLower(agent))
}

func (b *profileAgentBridge) unresolvedLegacy(agent string) func(string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now := time.Now(); !now.Before(b.readAt) {
		if ledger, ok := b.readLedger(); ok {
			b.ambiguous, b.derived, b.readAt = ledger.ambiguous, ledger.derived, now.Add(profileAgentBridgeRefresh)
		} else {
			b.readAt = now.Add(profileAgentBridgeRetry)
			if b.ambiguous == nil && !b.noted[""] {
				b.note("")
				fmt.Fprintf(os.Stderr, "[guardrail] the agent ledger cannot be read: an agent that a profile assignment's agents entries do not name "+
					"gets the default profile (default_lookup_failed) where such an assignment comes first, until the ledger answers\n")
			}
		}
	}
	if b.ambiguous == nil {
		// The ledger has not answered. The legacy identity the hook path
		// derived for agent is the only entry it can hold: another agent's
		// current identity is not its. Without that derivation, an exact
		// current-identity entry still selects agent (an unrelated earlier
		// entry must not send it to the outage default), and any other
		// entry may be agent's legacy identity.
		if legacy := derivedLegacyAgentID(agent); legacy != "" {
			if !b.entries[legacy] {
				return nil
			}
			return func(entry string) bool { return entry == legacy }
		}
		if b.entries[agent] {
			return nil
		}
		return func(entry string) bool { return entry != agent }
	}
	if entries := b.ambiguous[agent]; len(entries) > 0 {
		return func(entry string) bool { return entries[entry] }
	}
	// agent's own legacy identity, which no record links to it.
	legacy := b.derived[agent]
	if legacy == "" {
		legacy = derivedLegacyAgentID(agent)
	}
	if legacy == "" || !b.entries[legacy] {
		return nil
	}
	if !b.noted["?"+legacy] {
		b.note("?" + legacy)
		fmt.Fprintf(os.Stderr, "[guardrail] profile assignment agent %s: no record shows which account 1.0.3 recorded it for; "+
			"agent %s gets the default profile (default_lookup_failed) where it applies until it names the account's current agent identity\n",
			legacy, agent)
	}
	return func(entry string) bool { return entry == legacy }
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
	// ambiguous maps an identity to the legacy entries it may hold but the
	// ledger does not prove.
	ambiguous map[string]map[string]bool
	// derived maps a recorded identity to its legacy identity, an entry.
	derived map[string]string
}

// readLedger lists identities that may hold a legacy entry. No historic row
// proves an assignment's original account, including a sole surviving row.
// It reads every record, including the ones a prune kept aside.
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
		if legacyID == "" || !b.entries[legacyID] {
			continue
		}
		if id != legacyID {
			if id == strings.ToLower(agentidentity.AgentID(in)) {
				links.derived[id] = legacyID
			}
			continue
		}
		if !b.noted[id] {
			b.note(id)
			fmt.Fprintf(os.Stderr, "[guardrail] profile assignment agent %s: a pre-1.0.4 ledger row cannot prove its account; "+
				"affected agents get the default profile (default_lookup_failed) until the assignment names the current agent identity\n", rec.AgentID)
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

// derivedLegacyAgentIDs maps the agent identities the hook path derived in
// this process to their legacy identities (agentidentity.LegacyAgentID), so
// an agent the ledger has not recorded yet is known by it too. Bounded:
// past the cap, an identity is known by its record only.
var derivedLegacyAgentIDs struct {
	sync.Mutex
	ids map[string]string
}

const derivedLegacyAgentIDsMax = 4096

// noteDerivedLegacyAgentID remembers in's legacy identity for its identity.
func noteDerivedLegacyAgentID(in agentidentity.Inputs) {
	legacy := strings.ToLower(agentidentity.LegacyAgentID(in))
	if legacy == "" {
		return
	}
	id := strings.ToLower(agentidentity.AgentID(in))
	derivedLegacyAgentIDs.Lock()
	defer derivedLegacyAgentIDs.Unlock()
	if derivedLegacyAgentIDs.ids == nil {
		derivedLegacyAgentIDs.ids = map[string]string{}
	}
	if _, known := derivedLegacyAgentIDs.ids[id]; known || len(derivedLegacyAgentIDs.ids) < derivedLegacyAgentIDsMax {
		derivedLegacyAgentIDs.ids[id] = legacy
	}
}

func derivedLegacyAgentID(agent string) string {
	derivedLegacyAgentIDs.Lock()
	defer derivedLegacyAgentIDs.Unlock()
	return derivedLegacyAgentIDs.ids[agent]
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
