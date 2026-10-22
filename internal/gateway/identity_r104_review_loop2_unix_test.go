// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// Review loop 2, findings 1 to 3, end to end on a managed gateway upgraded
// from 1.0.3, whose homes file names each uid's account and keeps no token.
// The agent ledger cannot be read. A local account's token shows
// continuity: its 1.0.3 assignment keeps applying, after a restart too, as
// the homes file proves its owner. So does a qualified SSSD account whose
// SID SSSD's default id mapping derives the uid from, by the homes file or
// its surviving 1.0.3 ledger record. An RFC 2307 uid's token does not, and
// its 1.0.3 identity is still the one 1.0.3 derived (before, the incarnation
// changed it and the assignment was dropped for the observe default); since
// review loop 3 the upgrade binds the entry to that first holder, so it
// keeps applying too, as it does for a uid no token is known for yet.
func TestUpgradedHomesFileProvesTheLegacyAssignmentOwner(t *testing.T) {
	agentIdentityTestSetup(t)
	stubProfileSources(t)
	profileAgentSource = requestAgentIdentity
	previousHomes, previousFacts := managedHookPeerHomes, identityFactsEnabled.Load()
	previousIncarnation, previousName, previousLedger := managedHookPeerAccountIncarnation, userScopedIdentityName, profileAgentLedger
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookPeerAccountIncarnation, userScopedIdentityName = previousHomes, previousIncarnation, previousName
		profileAgentLedger = previousLedger
		setIdentityFactsEnabled(previousFacts)
	})
	setIdentityFactsEnabled(true)
	const (
		localUID   = 41601
		rfc2307UID = 41602
		pendingUID = 41603
		mappedUID  = 297801105 // SSSD's default id mapping of RID 1105 (slice 1488 of S-1-5-21-7-7-7)
	)
	names := map[int]string{localUID: "alice", rfc2307UID: "alice", pendingUID: "alice", mappedUID: "alice@corp.example"}
	userScopedIdentityName = func(id string) string {
		uid, _ := strconv.Atoi(id)
		return names[uid]
	}
	profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) { return nil, false }
	var mu sync.Mutex
	tokens := map[int]string{localUID: "files", rfc2307UID: "sid:S-1-5-21-2-2-2-3301", mappedUID: "sid:S-1-5-21-7-7-7-1105"}
	managedHookPeerAccountIncarnation = func(account unixidentity.Account) (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		token, ok := tokens[account.UID]
		return token, ok
	}
	home := t.TempDir()
	store := filepath.Join(t.TempDir(), "peer-homes.json")
	legacyFile := map[string]map[string]string{}
	for uid, name := range names {
		legacyFile[strconv.Itoa(uid)] = map[string]string{"home": home, "name": name}
	}
	data, err := json.Marshal(legacyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store, data, 0o600); err != nil {
		t.Fatal(err)
	}
	start := func() {
		accounts := map[int]unixidentity.Account{}
		for uid, name := range names {
			accounts[uid] = unixidentity.Account{Name: name, UID: uid, Home: home}
		}
		managedHookPeerHomes = &managedHookPeerHomeCache{
			newResolver: func() unixidentity.Resolver { return &fakePeerHomeResolver{accounts: accounts} },
			now:         time.Now,
		}
		managedHookPeerHomes.setStore(store)
	}
	peer := func(uid int) context.Context {
		return withManagedHookPeer(context.Background(), managedHookPeer{UID: uid, Name: names[uid], Home: home})
	}
	legacyOf := func(uid int) (string, agentIdentityFacts) {
		t.Helper()
		facts := resolveHookAgentIdentity(peer(uid), agentHookRequest{ConnectorName: "codex"})
		if facts.ID == "" {
			t.Fatal("no agent identity")
		}
		return agentidentity.LegacyAgentID(agentidentity.Inputs{
			MachineHash: facts.MachineHash, UserID: strconv.Itoa(uid), Account: names[uid], Connector: "codex", InstallFP: facts.InstallFP,
		}), facts
	}
	hook := func(cfg *config.Config, uid int) (profileDecision, string) {
		api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
		ctx := context.WithValue(peer(uid), testVerifiedSubjectKey{}, profileSubject{UserID: strconv.Itoa(uid), UserName: "alice"})
		ctx = api.withGuardrailProfileDecision(ctx, "codex")
		return api.resolveProfile(ctx), api.agentHookMode(ctx, "codex")
	}
	start()

	local, _ := legacyOf(localUID)
	got, mode := hook(loop2Only(local, "relaxed", "strict", loop2Incomparable), localUID)
	loop2Kept(t, "local account, ledger unreadable", got, mode)

	rfc2307, facts := legacyOf(rfc2307UID)
	if !strings.EqualFold(facts.LegacyID, rfc2307) || facts.ID == agentidentity.AgentID(agentidentity.Inputs{
		MachineHash: facts.MachineHash, UserID: strconv.Itoa(rfc2307UID), Account: "alice", Connector: "codex", InstallFP: facts.InstallFP,
	}) {
		t.Fatalf("RFC 2307 uid: identity %q, 1.0.3 identity %q; want an incarnation-keyed identity and the 1.0.3 one %q", facts.ID, facts.LegacyID, rfc2307)
	}
	tight := map[string]config.GuardrailProfile{"tight": {Mode: "action", BlockAt: "low"}, "watch": {Mode: "observe"}}
	got, mode = hook(loop2Only(rfc2307, "tight", "watch", tight), rfc2307UID)
	if got.Name != "tight" || got.Match != profileMatchAgent || mode != "action" {
		t.Errorf("RFC 2307 uid: profile %+v, mode %q; want the entry's tight (action) as agent, never the observe default", got, mode)
	}
	got, mode = hook(loop2Only(rfc2307, "relaxed", "strict", loop2Incomparable), rfc2307UID)
	loop2Kept(t, "RFC 2307 uid, ledger unreadable", got, mode)

	pending, _ := legacyOf(pendingUID)
	got, mode = hook(loop2Only(pending, "relaxed", "strict", loop2Incomparable), pendingUID)
	loop2Kept(t, "no token known since the upgrade", got, mode)

	// The homes file now keeps the 1.0.3 name beside the tokens.
	stored, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	var kept map[string]managedHookPeerLast
	if err := json.Unmarshal(stored, &kept); err != nil {
		t.Fatal(err)
	}
	if kept[strconv.Itoa(localUID)].LegacyName != "alice" {
		t.Fatalf("homes file keeps %+v for the local uid; want its 1.0.3 name", kept[strconv.Itoa(localUID)])
	}
	start()
	got, mode = hook(loop2Only(local, "relaxed", "strict", loop2Incomparable), localUID)
	loop2Kept(t, "local account after a restart", got, mode)

	mapped, facts := legacyOf(mappedUID)
	got, mode = hook(loop2Only(mapped, "relaxed", "strict", loop2Incomparable), mappedUID)
	loop2Kept(t, "id-mapped SSSD account, ledger unreadable", got, mode)
	// Without the homes file's name, the surviving 1.0.3 record proves it;
	// a namesake of another domain recorded under the uid withdraws that.
	managedHookPeerHomes.mu.Lock()
	delete(managedHookPeerHomes.legacyNames, mappedUID)
	managedHookPeerHomes.mu.Unlock()
	row := inventory.AgentIdentityRecord{AgentID: mapped, UserID: strconv.Itoa(mappedUID), UserName: "alice@corp.example",
		Connector: "codex", InstallFP: facts.InstallFP, MachineHash: facts.MachineHash}
	records := []inventory.AgentIdentityRecord{row}
	profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) { return records, true }
	got, mode = hook(loop2Only(mapped, "relaxed", "strict", loop2Incomparable), mappedUID)
	loop2Kept(t, "id-mapped SSSD account, 1.0.3 record", got, mode)
	namesake := row
	namesake.AgentID, namesake.UserName = "agt-00000000000000aa", "alice@lab.example"
	records = append(records, namesake)
	got, _ = hook(loop2Only(mapped, "relaxed", "strict", loop2Incomparable), mappedUID)
	loop2Unproven(t, "id-mapped SSSD account with a namesake of another domain", got)
}
