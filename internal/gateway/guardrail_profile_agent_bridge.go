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
// linked to neither account: the assignment applies again once it names the
// account's current identity. Remove with agentidentity.LegacyAgentID.
type profileAgentBridge struct {
	once sync.Once
	// entries are the assignments' agents entries, lower-cased.
	entries map[string]bool
	mu      sync.Mutex
	// legacy maps an identity to the legacy entry linked to it; nil until
	// the ledger answered.
	legacy map[string]string
	// readAt is when the ledger is read again: a namesake recorded later
	// takes a link back.
	readAt time.Time
	// noted holds the ambiguous entries already logged.
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

// profileAgent is the agents entry the request's agent identity agent is
// matched as: agent, or, when no assignment names agent, the legacy
// identity an assignment names for the same account.
func (set *guardrailProfileSet) profileAgent(agent string) string {
	agent = strings.TrimSpace(agent)
	if set == nil || agent == "" {
		return agent
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
		return agent
	}
	if legacy := bridge.legacyOf(strings.ToLower(agent)); legacy != "" {
		return legacy
	}
	return agent
}

func (b *profileAgentBridge) legacyOf(agent string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now := time.Now(); !now.Before(b.readAt) {
		if legacy, ok := b.readLedger(); ok {
			b.legacy, b.readAt = legacy, now.Add(profileAgentBridgeRefresh)
		} else {
			b.readAt = now.Add(profileAgentBridgeRetry)
		}
	}
	return b.legacy[agent]
}

// readLedger links each legacy entry the ledger proves to the identity its
// account has now, and false when the ledger cannot be read.
func (b *profileAgentBridge) readLedger() (map[string]string, bool) {
	ids := make([]string, 0, len(b.entries))
	for entry := range b.entries {
		ids = append(ids, entry)
	}
	sort.Strings(ids)
	records, ok := profileAgentLedger(inventory.AgentIdentityFilter{AgentIDs: ids})
	if !ok {
		return nil, false
	}
	legacy := map[string]string{}
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
				return nil, false
			}
			uidRecords[rec.UserID] = held
		}
		if namesake := profileAgentNamesake(rec, held); namesake {
			if b.noted == nil {
				b.noted = map[string]bool{}
			}
			if !b.noted[id] {
				b.noted[id] = true
				fmt.Fprintf(os.Stderr, "[guardrail] profile assignment agent %s: recorded before the upgrade for more than one account of uid %s; "+
					"it is not applied until it names the account's current agent identity\n", rec.AgentID, rec.UserID)
			}
			continue
		}
		legacy[strings.ToLower(agentidentity.AgentID(in))] = id
	}
	return legacy, true
}

// profileAgentNamesake reports whether held, the ledger's records of rec's
// uid, include one of another domain's account of the same name on rec's
// machine: 1.0.3 recorded both as rec, under the last one's name.
func profileAgentNamesake(rec inventory.AgentIdentityRecord, held []inventory.AgentIdentityRecord) bool {
	key, domain := agentidentity.AccountKey(rec.UserName), agentidentity.AccountDomain(rec.UserName)
	for _, other := range held {
		if other.MachineHash != rec.MachineHash ||
			agentidentity.NormalizeUserID(other.UserID) != agentidentity.NormalizeUserID(rec.UserID) ||
			agentidentity.AccountKey(other.UserName) != key {
			continue
		}
		if otherDomain := agentidentity.AccountDomain(other.UserName); otherDomain != "" && otherDomain != domain {
			return true
		}
	}
	return false
}
