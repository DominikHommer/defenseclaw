// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"sort"
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
// linked to neither account, and it stays unresolved for both: an
// assignment with it selects the outage default for them (matchAgent) until
// it names the account's current identity. Remove with
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

// matchAgent is set.match for a request of the agent identity agent. When
// an agents entry may be the legacy identity of agent's account but the
// agent ledger does not prove it (it has not answered yet, or the entry was
// recorded for more than one account), an assignment with that entry whose
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

// profileAgent is the agents entry the request's agent identity agent is
// matched as: agent, or, when no assignment names agent, the legacy
// identity an assignment names for the same account. unresolved, when not
// nil, reports the entries that may be agent's legacy identity without the
// ledger proving it.
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
	if len(bridge.entries) == 0 || bridge.entries[strings.ToLower(agent)] {
		return agent, nil
	}
	legacy, unresolved := bridge.legacyOf(strings.ToLower(agent))
	if legacy != "" {
		return legacy, nil
	}
	return agent, unresolved
}

func (b *profileAgentBridge) legacyOf(agent string) (string, func(string) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now := time.Now(); !now.Before(b.readAt) {
		if legacy, ambiguous, ok := b.readLedger(); ok {
			b.legacy, b.ambiguous, b.readAt = legacy, ambiguous, now.Add(profileAgentBridgeRefresh)
		} else {
			b.readAt = now.Add(profileAgentBridgeRetry)
			if b.legacy == nil && !b.noted[""] {
				b.note("")
				fmt.Fprintf(os.Stderr, "[guardrail] the agent ledger cannot be read: an agent that a profile assignment's agents entries do not name "+
					"gets the default profile (default_lookup_failed) where such an assignment comes first, until the ledger answers\n")
			}
		}
	}
	if b.legacy == nil {
		// Any entry may be agent's legacy identity.
		return "", func(entry string) bool { return entry != agent }
	}
	if entries := b.ambiguous[agent]; len(entries) > 0 {
		return "", func(entry string) bool { return entries[entry] }
	}
	return b.legacy[agent], nil
}

func (b *profileAgentBridge) note(key string) {
	if b.noted == nil {
		b.noted = map[string]bool{}
	}
	b.noted[key] = true
}

// readLedger links each legacy entry the ledger proves to the identity its
// account has now, and lists the identities that may hold an entry it does
// not prove; false when the ledger cannot be read.
func (b *profileAgentBridge) readLedger() (map[string]string, map[string]map[string]bool, bool) {
	ids := make([]string, 0, len(b.entries))
	for entry := range b.entries {
		ids = append(ids, entry)
	}
	sort.Strings(ids)
	records, ok := profileAgentLedger(inventory.AgentIdentityFilter{AgentIDs: ids})
	if !ok {
		return nil, nil, false
	}
	legacy := map[string]string{}
	ambiguous := map[string]map[string]bool{}
	uidRecords := map[string][]inventory.AgentIdentityRecord{}
	for _, rec := range records {
		in := agentidentity.Inputs{
			MachineHash: rec.MachineHash, UserID: rec.UserID, Account: rec.UserName,
			Connector: rec.Connector, InstallFP: rec.InstallFP,
		}
		id := strings.ToLower(rec.AgentID)
		if !b.entries[id] || !strings.EqualFold(agentidentity.LegacyAgentID(in), id) {
			continue
		}
		held, read := uidRecords[rec.UserID]
		if !read {
			if held, ok = profileAgentLedger(inventory.AgentIdentityFilter{User: rec.UserID}); !ok {
				return nil, nil, false
			}
			uidRecords[rec.UserID] = held
		}
		if namesakes := profileAgentNamesakes(rec, held); len(namesakes) > 0 {
			if !b.noted[id] {
				b.note(id)
				fmt.Fprintf(os.Stderr, "[guardrail] profile assignment agent %s: recorded before the upgrade for more than one account of uid %s; "+
					"their agents get the default profile (default_lookup_failed) where it applies until it names the account's current agent identity\n",
					rec.AgentID, rec.UserID)
			}
			for _, account := range append(namesakes, rec.UserName) {
				holder := in
				holder.Account = account
				if current := strings.ToLower(agentidentity.AgentID(holder)); current != "" {
					if ambiguous[current] == nil {
						ambiguous[current] = map[string]bool{}
					}
					ambiguous[current][id] = true
				}
			}
			continue
		}
		legacy[strings.ToLower(agentidentity.AgentID(in))] = id
	}
	return legacy, ambiguous, true
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
