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
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review loop 3, finding 1, end to end on a managed gateway upgraded from
// 1.0.3 (its homes file names each uid's account and keeps no token), with
// the agent ledger unreadable. Tokens that show no continuity (an RFC 2307
// or winbind SID, a macOS listed record) left each 1.0.3 agents entry a
// maybe, and profiles that do not cover each other refused every hook the
// exact agent ID matched in 1.0.3. The upgrade now binds the entries to the
// first account the gateway sees hold the uid, under the 1.0.3 name: they
// keep applying, after a restart too. A first holder with another domain's
// name, or a later account that takes the uid over, is not bound.
func TestUpgradeBindsLegacyAssignmentsToTheFirstHolderWhateverItsToken(t *testing.T) {
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
		rfc2307UID = 41701
		recordUID  = 41702
		winbindUID = 41703
		renamedUID = 41704
	)
	legacyNames := map[int]string{rfc2307UID: "alice@corp.example", recordUID: "bob", winbindUID: "carol", renamedUID: "dave@corp.example"}
	var mu sync.Mutex
	names := map[int]string{rfc2307UID: "alice@corp.example", recordUID: "bob", winbindUID: "carol", renamedUID: "dave@lab.example"}
	tokens := map[int]string{
		rfc2307UID: "sid:S-1-5-21-2-2-2-3301", recordUID: "record:5f1c0a1e00004000",
		winbindUID: "sid:S-1-5-21-3-3-3-1203", renamedUID: "sid:S-1-5-21-4-4-4-1001",
	}
	userScopedIdentityName = func(id string) string {
		uid, _ := strconv.Atoi(id)
		mu.Lock()
		defer mu.Unlock()
		return names[uid]
	}
	profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) { return nil, false }
	managedHookPeerAccountIncarnation = func(account unixidentity.Account) (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		token, ok := tokens[account.UID]
		return token, ok
	}
	home := t.TempDir()
	store := filepath.Join(t.TempDir(), "peer-homes.json")
	legacyFile := map[string]map[string]string{}
	for uid, name := range legacyNames {
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
		mu.Lock()
		accounts := map[int]unixidentity.Account{}
		for uid, name := range names {
			accounts[uid] = unixidentity.Account{Name: name, UID: uid, Home: home}
		}
		mu.Unlock()
		managedHookPeerHomes = &managedHookPeerHomeCache{
			newResolver: func() unixidentity.Resolver { return &fakePeerHomeResolver{accounts: accounts} },
			now:         time.Now,
		}
		managedHookPeerHomes.setStore(store)
	}
	peer := func(uid int) context.Context {
		mu.Lock()
		defer mu.Unlock()
		return withManagedHookPeer(context.Background(), managedHookPeer{UID: uid, Name: names[uid], Home: home})
	}
	legacyOf := func(uid int) string {
		t.Helper()
		facts := resolveHookAgentIdentity(peer(uid), agentHookRequest{ConnectorName: "codex"})
		if facts.ID == "" {
			t.Fatal("no agent identity")
		}
		mu.Lock()
		name := names[uid]
		mu.Unlock()
		legacy := agentidentity.LegacyAgentID(agentidentity.Inputs{
			MachineHash: facts.MachineHash, UserID: strconv.Itoa(uid), Account: name, Connector: "codex", InstallFP: facts.InstallFP,
		})
		if !strings.EqualFold(facts.LegacyID, legacy) {
			t.Fatalf("uid %d: 1.0.3 identity %q; want %q", uid, facts.LegacyID, legacy)
		}
		return legacy
	}
	hook := func(cfg *config.Config, uid int) (profileDecision, string) {
		api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
		ctx := context.WithValue(peer(uid), testVerifiedSubjectKey{}, profileSubject{UserID: strconv.Itoa(uid), UserName: "alice"})
		ctx = api.withGuardrailProfileDecision(ctx, "codex")
		return api.resolveProfile(ctx), api.agentHookMode(ctx, "codex")
	}
	tight := map[string]config.GuardrailProfile{"tight": {Mode: "action", BlockAt: "low"}, "watch": {Mode: "observe"}}
	start()

	kept := map[int]string{rfc2307UID: "RFC 2307 uid", recordUID: "macOS listed record", winbindUID: "winbind SID"}
	legacy := map[int]string{}
	for uid, what := range kept {
		legacy[uid] = legacyOf(uid)
		got, mode := hook(loop2Only(legacy[uid], "relaxed", "strict", loop2Incomparable), uid)
		loop2Kept(t, what, got, mode)
		if got, mode := hook(loop2Only(legacy[uid], "tight", "watch", tight), uid); got.Name != "tight" || got.Match != profileMatchAgent || mode != "action" {
			t.Errorf("%s: %+v, mode %q; want the entry's tight (action) as agent", what, got, mode)
		}
	}
	renamed := legacyOf(renamedUID)
	got, _ := hook(loop2Only(renamed, "relaxed", "strict", loop2Incomparable), renamedUID)
	loop2Unproven(t, "first holder named in another domain than 1.0.3 named it", got)

	// The homes file keeps the bound token, so a restart keeps the binding.
	stored, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]managedHookPeerLast
	if err := json.Unmarshal(stored, &persisted); err != nil {
		t.Fatal(err)
	}
	if last := persisted[strconv.Itoa(rfc2307UID)]; last.BaseIncarnation != agentIncarnationUnproven || last.UpgradeIncarnation != tokens[rfc2307UID] {
		t.Fatalf("homes file keeps %+v for the RFC 2307 uid; want its first token as the upgrade binding", last)
	}
	start()
	for uid, what := range kept {
		got, mode := hook(loop2Only(legacyOf(uid), "relaxed", "strict", loop2Incomparable), uid)
		loop2Kept(t, what+" after a restart", got, mode)
	}

	// Another account takes the RFC 2307 uid and the macOS record's uid
	// over (another SID, another record): not bound, strictest or refused.
	mu.Lock()
	tokens[rfc2307UID], tokens[recordUID] = "sid:S-1-5-21-2-2-2-9999", "record:0000000000000000"
	mu.Unlock()
	start()
	for _, uid := range []int{rfc2307UID, recordUID} {
		entry := legacyOf(uid)
		got, _ := hook(loop2Only(entry, "relaxed", "strict", loop2Incomparable), uid)
		loop2Unproven(t, kept[uid]+" taken over by another account", got)
		if got, mode := hook(loop2Only(entry, "tight", "watch", tight), uid); got.Name != "tight" || got.Match != profileMatchDefaultLookupFailed || mode != "action" {
			t.Errorf("%s taken over: %+v, mode %q; want tight as default_lookup_failed, never the observe default", kept[uid], got, mode)
		}
	}
	// The winbind uid's holder is unchanged.
	got, mode := hook(loop2Only(legacyOf(winbindUID), "relaxed", "strict", loop2Incomparable), winbindUID)
	loop2Kept(t, "winbind SID, holder unchanged", got, mode)
}

// Review loop 3, finding 2: a macOS account's local node record names its
// incarnation by a digest that has no control bytes (the listed record
// joins its fields with NUL) and differs for every other record.
func TestAccountRecordTokenNamesTheRecord(t *testing.T) {
	if got := accountRecordToken(""); got != "" {
		t.Fatalf("no record: %q; want none", got)
	}
	a, b := accountRecordToken("501\x00GUID-A\x00/Users/alice\x0020"), accountRecordToken("501\x00GUID-B\x00/Users/alice\x0020")
	if a == "" || a == b || !strings.HasPrefix(a, "record:") || !validAccountToken(a) {
		t.Fatalf("record tokens %q and %q; want two valid, distinct record: tokens", a, b)
	}
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: "501", IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{AccountRecord: a}}, false)
	if subject.accountToken != a {
		t.Fatalf("subject token %q; want the record's %q", subject.accountToken, a)
	}
}
