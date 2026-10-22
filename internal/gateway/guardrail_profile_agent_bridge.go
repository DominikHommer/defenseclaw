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
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// profileAgentBridge decides, for the agents entries an assignment wrote for
// a legacy identity (1.0.0 to 1.0.3: keyed without the account's domain and
// without an account incarnation, agentidentity.LegacyAgentID), whether an
// entry is the request agent's own. 1.0.3 gave one legacy identity to every
// domain's namesake of a uid and to every account that took the uid over,
// so the entry is the agent's own only when the gateway proves it
// (profileAgentBridge.provesLocked):
//
//   - the request's facts derive the entry as their 1.0.3 identity;
//   - the account incarnation that holds the uid now is the one the upgrade
//     bound the uid's 1.0.3 identities to: the per-user gateway's own
//     account, or the first account this gateway saw hold the uid after the
//     upgrade, whatever its token (a local account, an SSSD SID, an RFC 2307
//     uid, a macOS record), which still holds it
//     (managedHookPeerHomeCache.legacyProof, profileAgentClaim.Bound);
//   - the build before 1.0.4 named that account as the host names it now: the
//     name its homes file kept for the uid (managedHookPeerHomeCache.legacyName),
//     which no ledger prune or outage removes, or else the 1.0.3 ledger
//     record of the entry; one account, domain included (GAP-0424, GAP-1055);
//   - no ledger record shows the uid held, on the machine, under that name in
//     another domain or without one (GAP-0337).
//
// A proven entry matches as the agent's current identity does, so a 1.0.3
// assignment keeps working after the upgrade without a rebind. Any other
// entry the request derives stays unresolved: the request gets the strictest
// profile of those that may apply, or is refused (selectProfile), never a
// weaker default and never silently none. Remove with
// agentidentity.LegacyAgentID.
type profileAgentBridge struct {
	once sync.Once
	// entries are the assignments' agents entries, lower-cased.
	entries map[string]bool
	mu      sync.Mutex
	// links is what the agent ledger said at its last read; read is false
	// until it answered once.
	links profileAgentLinks
	read  bool
	// readAt is when the ledger is read again: a namesake recorded later
	// withdraws a proof.
	readAt time.Time
	// noted holds the entries already logged; "" the unreadable ledger.
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

// profileAgentClaim is the 1.0.3 identity of an agent and what the bridge
// proves it by.
type profileAgentClaim struct {
	// ID is the 1.0.3 identity (agentidentity.LegacyAgentID), lower-cased;
	// "" when the agent's identity did not change (a SID).
	ID string
	// UserID, MachineHash and Account are the facts ID was derived from:
	// Account is the account as the host names it now.
	UserID, MachineHash, Account string
	// Bound reports that the account incarnation that holds UserID now is
	// the one the build before 1.0.4 saw (profileAgentBridge).
	Bound bool
	// Name is the name the build before 1.0.4 gave UserID: the account
	// itself for a per-user gateway, else its homes file's; "" when unknown.
	Name string
	// Incarnation is, in a claim the ledger derives (profileAgentLinks),
	// the account incarnation the record's identity was derived with.
	Incarnation string
}

// legacyAgentClaim is the claim of the 1.0.3 identity legacy derived for the
// account account that holds userID on machine. incarnation is the account
// incarnation the current identity was derived with
// (agentidentity.Inputs.Incarnation): only the account the upgrade bound
// the uid's 1.0.3 identities to (managedHookPeerHomeCache.legacyProof), and
// only with its own incarnation, is bound; any other account that held or
// holds the uid is not. self marks a per-user gateway's own account.
func legacyAgentClaim(legacy, userID, machine, account, incarnation string, self bool) profileAgentClaim {
	claim := profileAgentClaim{
		ID:     strings.ToLower(strings.TrimSpace(legacy)),
		UserID: agentidentity.NormalizeUserID(userID), MachineHash: machine, Account: account,
	}
	if claim.ID == "" {
		return claim
	}
	if self {
		claim.Bound, claim.Name = true, account
		return claim
	}
	name, boundIncarnation, bound := agentIdentityLegacyProof(claim.UserID)
	claim.Bound, claim.Name = bound && strings.TrimSpace(incarnation) == boundIncarnation, name
	return claim
}

// profileAgentSelf reports whether userID is a per-user gateway's own
// account, which only it can be the verified user of.
func profileAgentSelf(userID string) bool {
	if gatewayRunsAsServiceAccount() {
		return false
	}
	self := agentidentity.NormalizeUserID(gatewaySelfUser().ID)
	return self != "" && self == agentidentity.NormalizeUserID(userID)
}

// profileAgentLegacy returns the 1.0.3 identity of a request's agent with
// its proof (profileAgentClaim) and true, or false when it is not known.
type profileAgentLegacy func() (claim profileAgentClaim, known bool)

// matchAgent is set.match for a request of the agent identity agent;
// legacy, when not nil, derives agent's 1.0.3 identity. An agents entry that
// may be that identity, which the bridge does not prove the agent's own,
// leaves the agent fact unproven (resolveIdentity): an assignment with that
// entry whose other conditions hold may apply, and the one selection rule
// gives the request the strictest profile of those that may apply, or
// refuses it (selectProfile). An entry the bridge proves matches as agent
// does.
func (set *guardrailProfileSet) matchAgent(subject *profileSubject, source, connectorName, agent string, legacy profileAgentLegacy) profileDecision {
	matched, unresolved, owned := set.profileAgent(agent, legacy)
	if subject == nil || source == "" {
		unresolved, owned = nil, nil
	}
	res := resolveIdentity(subject, unresolved)
	if owned != nil {
		// A later ledger read can withdraw the proof (a namesake of another
		// domain recorded since), so the decision is not memoised.
		res.agentOwned = owned
		return set.selectProfile(subject, res, source, connectorName, matched)
	}
	return set.matchResolved(subject, res, source, connectorName, matched)
}

// profileAgent is what the request's agent identity agent is matched as
// (match's agent argument): agent itself. unresolved, when not nil, reports
// the entries that may be agent's 1.0.3 identity, which the bridge does not
// prove; matchAgent then lets no later assignment, one naming agent
// included, apply in place of an earlier one with such an entry. owned,
// when not nil, reports the entry the bridge proves is agent's own 1.0.3
// identity: it matches as agent does.
func (set *guardrailProfileSet) profileAgent(agent string, legacy profileAgentLegacy) (matched string, unresolved, owned func(entry string) bool) {
	agent = strings.TrimSpace(agent)
	if set == nil || agent == "" {
		return agent, nil, nil
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
		return agent, nil, nil
	}
	var claim profileAgentClaim
	known := false
	if legacy != nil {
		claim, known = legacy()
		claim.ID = strings.ToLower(strings.TrimSpace(claim.ID))
	}
	if known && (claim.ID == "" || !bridge.entries[claim.ID]) {
		// No entry is agent's 1.0.3 identity.
		return agent, nil, nil
	}
	unresolved, owned = bridge.resolve(strings.ToLower(agent), claim, known)
	return agent, unresolved, owned
}

// resolve is profileAgent's ledger side. claim is agent's when known; else
// (explain names an agent by its identity only) the ledger's records of
// agent say what its 1.0.3 identity is.
func (b *profileAgentBridge) resolve(agent string, claim profileAgentClaim, known bool) (unresolved, owned func(string) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshLocked()
	if !known {
		recorded, ok := b.links.derived[agent]
		if !b.read || !ok {
			// Neither the request nor the ledger says what agent's 1.0.3
			// identity is: any entry may be it.
			return func(entry string) bool { return entry != agent }, nil
		}
		if recorded.ID == "" || !b.entries[recorded.ID] {
			return nil, nil
		}
		claim = legacyAgentClaim(recorded.ID, recorded.UserID, recorded.MachineHash, recorded.Account, recorded.Incarnation, profileAgentSelf(recorded.UserID))
	}
	legacy := claim.ID
	if b.provesLocked(claim) {
		if !b.noted["="+legacy] {
			b.note("=" + legacy)
			fmt.Fprintf(os.Stderr, "[guardrail] profile assignment agent %s: the 1.0.3 identity of %s's agent %s, which it keeps; "+
				"replace the entry with %s\n", legacy, claim.Account, agent, agent)
		}
		return nil, func(entry string) bool { return entry == legacy }
	}
	if !b.noted["?"+legacy] {
		b.note("?" + legacy)
		fmt.Fprintf(os.Stderr, "[guardrail] profile assignment agent %s: nothing proves that the account holding uid %s now is the one 1.0.3 recorded it for; "+
			"agent %s gets the strictest profile that may apply (default_lookup_failed) where it applies until the assignment names the account's current agent identity\n",
			legacy, claim.UserID, agent)
	}
	return func(entry string) bool { return entry == legacy }, nil
}

// refreshLocked reads the ledger again once its answer is due. b.mu is held.
func (b *profileAgentBridge) refreshLocked() {
	now := time.Now()
	if now.Before(b.readAt) {
		return
	}
	if links, ok := b.readLedger(); ok {
		b.links, b.read, b.readAt = links, true, now.Add(profileAgentBridgeRefresh)
		return
	}
	b.readAt = now.Add(profileAgentBridgeRetry)
	if !b.read && !b.noted[""] {
		b.note("")
		fmt.Fprintf(os.Stderr, "[guardrail] the agent ledger cannot be read: a 1.0.3 agents entry of an account no homes record proves "+
			"gets the strictest profile that may apply (default_lookup_failed) where it comes first, until the ledger answers\n")
	}
}

// provesLocked reports whether claim's 1.0.3 identity is its account's own
// (profileAgentBridge). b.mu is held.
func (b *profileAgentBridge) provesLocked(claim profileAgentClaim) bool {
	if !claim.Bound || agentidentity.AccountKey(claim.Account) == "" {
		return false
	}
	name := claim.Name
	if b.read {
		if b.links.otherDomain(claim) {
			return false
		}
		if name == "" {
			name = b.links.recorded[claim.ID]
		}
	}
	return name != "" && agentidentity.AccountKey(name) == agentidentity.AccountKey(claim.Account) &&
		agentidentity.AccountDomain(name) == agentidentity.AccountDomain(claim.Account)
}

func (b *profileAgentBridge) note(key string) {
	if b.noted == nil {
		b.noted = map[string]bool{}
	}
	b.noted[key] = true
}

// profileAgentLinks is what the agent ledger says about the assignments'
// 1.0.3 entries.
type profileAgentLinks struct {
	// recorded maps a 1.0.3 entry to the account its 1.0.3 record names.
	recorded map[string]string
	// domains maps a machine, uid and account name (profileAgentHolder) to
	// the domains ("" for none) the ledger's records name it with.
	domains map[string]map[string]bool
	// derived maps every identity the ledger's records derive to its 1.0.3
	// claim, without proof: explain names an agent by its identity only.
	derived map[string]profileAgentClaim
}

// otherDomain reports whether a record shows claim's uid held on its
// machine by an account of its name in another domain or without one: 1.0.3
// gave both one identity and kept one record for both (GAP-0337).
func (l profileAgentLinks) otherDomain(claim profileAgentClaim) bool {
	domain := agentidentity.AccountDomain(claim.Account)
	for recorded := range l.domains[profileAgentHolder(claim.MachineHash, claim.UserID, claim.Account)] {
		if recorded != domain {
			return true
		}
	}
	return false
}

func profileAgentHolder(machine, userID, account string) string {
	return machine + "\x00" + agentidentity.NormalizeUserID(userID) + "\x00" + agentidentity.AccountKey(account)
}

// readLedger reads every record, the ones a prune kept aside included
// (inventory.retireLegacyAgentIdentities); false when the ledger cannot be
// read.
func (b *profileAgentBridge) readLedger() (profileAgentLinks, bool) {
	records, ok := profileAgentLedger(inventory.AgentIdentityFilter{Retired: true})
	if !ok {
		return profileAgentLinks{}, false
	}
	links := profileAgentLinks{recorded: map[string]string{}, domains: map[string]map[string]bool{}, derived: map[string]profileAgentClaim{}}
	for _, rec := range records {
		if agentidentity.IsSID(agentidentity.NormalizeUserID(rec.UserID)) || agentidentity.AccountKey(rec.UserName) == "" {
			continue
		}
		holder := profileAgentHolder(rec.MachineHash, rec.UserID, rec.UserName)
		if links.domains[holder] == nil {
			links.domains[holder] = map[string]bool{}
		}
		links.domains[holder][agentidentity.AccountDomain(rec.UserName)] = true
		in := agentidentity.Inputs{
			MachineHash: rec.MachineHash, UserID: rec.UserID, Account: rec.UserName,
			Connector: rec.Connector, InstallFP: rec.InstallFP,
		}
		legacy := strings.ToLower(agentidentity.LegacyAgentID(in))
		if legacy == "" {
			continue
		}
		id, current := strings.ToLower(rec.AgentID), strings.ToLower(agentidentity.AgentID(in))
		claim := profileAgentClaim{ID: legacy, UserID: agentidentity.NormalizeUserID(rec.UserID), MachineHash: rec.MachineHash, Account: rec.UserName}
		switch {
		case id == legacy:
			// A 1.0.3 record: it names the account 1.0.3 last recorded the
			// entry for, and derives that account's current identity.
			if _, seen := links.recorded[id]; !seen && b.entries[id] {
				links.recorded[id] = rec.UserName
			}
			if _, seen := links.derived[current]; !seen {
				links.derived[current] = claim
			}
		case id == current:
			links.derived[id] = claim
		case strings.TrimSpace(rec.UserIncarnation) != "":
			// An identity derived with an account incarnation: never bound.
			in.Incarnation = rec.UserIncarnation
			if id == strings.ToLower(agentidentity.AgentID(in)) {
				claim.Incarnation = rec.UserIncarnation
				links.derived[id] = claim
			}
		}
	}
	return links, true
}
