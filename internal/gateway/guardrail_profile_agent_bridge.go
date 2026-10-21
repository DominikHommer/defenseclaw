// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
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
// proves the link: the legacy identity's record names the account it was
// derived for, and that account's identity now is the one a request
// carries. A namesake from another domain that is given the uid later
// derives another identity and is not linked (GAP-1055). Remove with
// agentidentity.LegacyAgentID.
type profileAgentBridge struct {
	once sync.Once
	// entries are the assignments' agents entries, lower-cased.
	entries map[string]bool
	mu      sync.Mutex
	// legacy maps an identity to the legacy entry linked to it; nil until
	// the ledger answered.
	legacy  map[string]string
	retryAt time.Time
}

// profileAgentBridgeRetry is how long a ledger that could not be read is
// left alone.
const profileAgentBridgeRetry = 30 * time.Second

// profileAgentLedger returns the agent ledger's records of ids, and false
// when the ledger cannot be read now.
var profileAgentLedger = func(ids []string) ([]inventory.AgentIdentityRecord, bool) {
	store := sharedAgentIdentities.store()
	if store == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	records, _, err := store.ListAgentIdentities(ctx, inventory.AgentIdentityFilter{AgentIDs: ids})
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
	if b.legacy == nil && !time.Now().Before(b.retryAt) {
		ids := make([]string, 0, len(b.entries))
		for entry := range b.entries {
			ids = append(ids, entry)
		}
		sort.Strings(ids)
		records, ok := profileAgentLedger(ids)
		if !ok {
			b.retryAt = time.Now().Add(profileAgentBridgeRetry)
			return ""
		}
		legacy := map[string]string{}
		for _, rec := range records {
			in := agentidentity.Inputs{
				MachineHash: rec.MachineHash, UserID: rec.UserID, Account: rec.UserName,
				Connector: rec.Connector, InstallFP: rec.InstallFP,
			}
			id := strings.ToLower(rec.AgentID)
			if b.entries[id] && strings.EqualFold(agentidentity.LegacyAgentID(in), id) {
				legacy[strings.ToLower(agentidentity.AgentID(in))] = id
			}
		}
		b.legacy = legacy
	}
	return b.legacy[agent]
}
