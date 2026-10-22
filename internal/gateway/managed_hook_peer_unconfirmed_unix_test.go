// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// strictGroupCheck assigns the strict action profile to group and makes
// the default an observe profile, so the failed-lookup default has fewer
// guards than the group's profile. The check it returns says whether the
// facts a hook call of uid got select the strict profile.
func strictGroupCheck(t *testing.T, group string) func(step string, uid int, name string, facts useridentity.DirectoryFacts, ok bool) error {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Mode: "action"}, "open": {Mode: "observe"}}
	cfg.Guardrail.DefaultProfile = "open"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{group}}},
	}
	profiles, err := cfg.DeriveGuardrailProfiles()
	if err != nil {
		t.Fatal(err)
	}
	set := &guardrailProfileSet{base: cfg, profiles: profiles, assignments: cfg.Guardrail.ProfileAssignments, defaultProfile: "open"}
	return func(step string, uid int, name string, facts useridentity.DirectoryFacts, ok bool) error {
		subject := profileSubjectFromVerified(VerifiedSubject{
			UserID: strconv.Itoa(uid), IDKind: useridentity.KindForID(strconv.Itoa(uid)), UserName: name, Directory: facts,
		}, true)
		if !ok {
			subject.LookupFailed = true
		}
		decision := set.match(&subject, profileSubjectVerified, "claudecode", "")
		if decision.Name != "strict" || profiles[decision.Name].Config.Guardrail.Mode != "action" {
			return fmt.Errorf("%s: facts=%+v ok=%v gave %+v; want the confirmed group's strict action profile", step, facts, ok, decision)
		}
		return nil
	}
}

// The stamp a request reads after the listing expired: the refresh it starts
// when that ends inside the wait, else the last listing, never none.
func TestAccountsSourceWaitsForTheRefreshThenServesTheLastListing(t *testing.T) {
	listing := &listedAccounts{accounts: byUID(map[string]int{"alice": 501})}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	s := &managedHookPeerAccountsSource{stat: unreadableStat, list: listing.list, now: func() time.Time { return time.Unix(0, clock.Load()) }}
	first := s.get()
	if first == "" || s.record("alice") == "" {
		t.Fatal("the first request did not wait for the first listing")
	}
	record := s.record("alice")

	// The refresh hangs: the request waits for it, then gets the last listing.
	listing.set(byUID(map[string]int{"alice": 502}))
	gate := make(chan struct{})
	listing.mu.Lock()
	listing.gate = gate
	listing.mu.Unlock()
	clock.Add(int64(managedHookPeerListedStampInterval))
	start := time.Now()
	if got := s.get(); got != first {
		t.Fatalf("expired listing with a hung refresh = %q, want the last listing %q", got, first)
	}
	if waited := time.Since(start); waited < managedHookPeerListedStampWait-50*time.Millisecond {
		t.Fatalf("the request waited %s for the refresh, want about %s", waited, managedHookPeerListedStampWait)
	}
	if got := s.record("alice"); got != record {
		t.Fatalf("record while the refresh hangs = %q, want the last listing's %q", got, record)
	}
	start = time.Now()
	if got := s.get(); got != first || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("a later request = %q after %s: it must not wait again for the same refresh", got, time.Since(start))
	}
	listing.mu.Lock()
	listing.gate = nil
	listing.mu.Unlock()
	close(gate)
	waitListed(t, s)
	second := s.get()
	if second == first || second == "" {
		t.Fatalf("after the refresh = %q, want the new listing", second)
	}

	// A refresh that ends inside the wait decides the request.
	listing.set(byUID(map[string]int{"alice": 503}))
	gate = make(chan struct{})
	listing.mu.Lock()
	listing.gate = gate
	listing.mu.Unlock()
	clock.Add(int64(managedHookPeerListedStampInterval))
	go func() {
		time.Sleep(50 * time.Millisecond)
		listing.mu.Lock()
		listing.gate = nil
		listing.mu.Unlock()
		close(gate)
	}()
	want, _ := localAccountsListing(byUID(map[string]int{"alice": 503}))
	if got := s.get(); got != want.stamp {
		t.Fatalf("a refresh that ended inside the wait = %q, want %q", got, want.stamp)
	}
}

// Finding (loop round 3): a strict group profile over an observe default.
// The first hook after each listing expiry got no directory facts while the
// refresh ran and fell to the observe default. It now waits for the refresh
// and, past the wait, keeps the confirmed account's facts.
func TestL1ExpiredListingKeepsTheConfirmedProfileWhileTheRefreshRuns(t *testing.T) {
	const uid = 94401
	record := unixidentity.LocalAccountRecord{UID: uid, RecordID: "0D4E", Home: "/Users/Shared/carol", PrimaryGID: "20"}
	resolver := &changingHolderAccounts{accounts: map[int]unixidentity.Account{uid: {Name: "carol", UID: uid, Home: record.Home}}}
	facts := &accountFacts{groups: []string{"staff", "dc-strict"}}
	listing := &listedAccounts{accounts: map[string]unixidentity.LocalAccountRecord{"carol": record}}
	installListedAccounts(t, listing, factsTestCache(t, resolver, facts))
	managedHookPeerAccountsRefresh()
	strict := strictGroupCheck(t, "dc-strict")
	check := func(step string) {
		t.Helper()
		got, ok := managedHookPeerDirectory(uid, true)
		if err := strict(step, uid, "carol", got, ok); err != nil {
			t.Fatal(err)
		}
	}
	check("confirmed")

	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	managedHookPeerAccounts.now = func() time.Time { return time.Unix(0, clock.Load()) }
	expire := func() { clock.Add(int64(2 * managedHookPeerListedStampInterval)) }

	// The refresh hangs past the wait.
	gate := make(chan struct{})
	listing.mu.Lock()
	listing.gate = gate
	listing.mu.Unlock()
	expire()
	check("first hook after the expiry, refresh hung")
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, ok := managedHookPeerDirectory(uid, true)
			if err := strict("concurrent hook while the refresh hangs", uid, "carol", got, ok); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	listing.mu.Lock()
	listing.gate = nil
	listing.mu.Unlock()
	close(gate)
	waitListed(t, managedHookPeerAccounts)
	check("after the refresh")

	// The refresh ends inside the wait.
	gate = make(chan struct{})
	listing.mu.Lock()
	listing.gate = gate
	listing.mu.Unlock()
	expire()
	go func() {
		time.Sleep(50 * time.Millisecond)
		listing.mu.Lock()
		listing.gate = nil
		listing.mu.Unlock()
		close(gate)
	}()
	check("refresh inside the wait")
	if facts.count() != 1 {
		t.Fatalf("the unchanged account was looked up %d times, want its cached facts", facts.count())
	}
}

// gatedPeerResolver answers from accounts; while gate is set, a lookup
// waits on it (a directory that answers slowly).
type gatedPeerResolver struct {
	unixidentity.Resolver
	mu       sync.Mutex
	accounts map[int]unixidentity.Account
	gate     chan struct{}
	calls    atomic.Int32
}

func (r *gatedPeerResolver) LookupUID(uid int) (unixidentity.Account, error) {
	r.calls.Add(1)
	r.mu.Lock()
	gate := r.gate
	account, ok := r.accounts[uid]
	r.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if !ok {
		return unixidentity.Account{}, unixidentity.ErrNotFound
	}
	return account, nil
}

func (r *gatedPeerResolver) hold() chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gate = make(chan struct{})
	return r.gate
}

func (r *gatedPeerResolver) release(gate chan struct{}) {
	r.mu.Lock()
	r.gate = nil
	r.mu.Unlock()
	close(gate)
}

// Finding (loop round 3): after the 1 s recheck interval, an account lookup
// slower than the 250 ms budget returned no account, and a strict group's
// member fell to the observe default. A slow recheck, or a slow lookup after
// the resolver's lifetime with no account database change, keeps the
// confirmed account as one the directory cannot answer does. After an
// account database change nothing is confirmed: the uid may hold another
// account (GAP-0947), so its former facts are not served.
func TestSlowAccountLookupKeepsTheConfirmedProfile(t *testing.T) {
	const uid = 41401
	previousFacts, previousIncarnation, previousSource := identityFactsEnabled.Load(), managedHookPeerAccountIncarnation, managedHookPeerAccounts
	previousManaged := ManagedEnterpriseActive()
	var stamp atomic.Value
	stamp.Store("passwd-1")
	managedHookPeerAccounts = &managedHookPeerAccountsSource{stat: func() string { return stamp.Load().(string) }, now: time.Now}
	setIdentityFactsEnabled(true)
	SetManagedEnterpriseActive(false)
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "files", true }
	t.Cleanup(func() {
		setIdentityFactsEnabled(previousFacts)
		SetManagedEnterpriseActive(previousManaged)
		managedHookPeerAccountIncarnation, managedHookPeerAccounts = previousIncarnation, previousSource
	})
	resolver := &gatedPeerResolver{accounts: map[int]unixidentity.Account{uid: {Name: "dave", UID: uid, Home: "/home/dave"}}}
	var clock sync.Mutex
	now := time.Unix(5_000_000, 0)
	advance := func(d time.Duration) {
		clock.Lock()
		now = now.Add(d)
		clock.Unlock()
	}
	cache := &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver { return resolver },
		now: func() time.Time {
			clock.Lock()
			defer clock.Unlock()
			return now
		},
	}
	var lookups atomic.Int32
	cache.directoriesOnce.Do(func() {
		cache.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
			lookups.Add(1)
			return useridentity.DirectoryFacts{Groups: []string{"dc-strict"}, ResolvedAt: time.Now()}, nil
		})
	})
	strict := strictGroupCheck(t, "dc-strict")
	got, ok := cache.directory(uid, true)
	if err := strict("confirmed", uid, "dave", got, ok); err != nil {
		t.Fatal(err)
	}

	slow := func(step string, change func()) {
		t.Helper()
		gate := resolver.hold()
		change()
		start := time.Now()
		got, ok := cache.directory(uid, true)
		if waited := time.Since(start); waited > managedHookPeerAccountBudget+time.Second {
			resolver.release(gate)
			t.Fatalf("%s: the hook waited %s for a slow lookup", step, waited)
		}
		if err := strict(step, uid, "dave", got, ok); err != nil {
			resolver.release(gate)
			t.Fatal(err)
		}
		// Requests while the lookup still runs share it and get the same.
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, ok := cache.directory(uid, true)
				if err := strict(step+", concurrent", uid, "dave", got, ok); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		resolver.release(gate)
	}
	slow("slow recheck", func() { advance(2 * managedHookPeerAccountRecheck) })
	// The recheck answered the same account: its facts were kept.
	deadline := time.Now().Add(5 * time.Second)
	for {
		cache.mu.Lock()
		pending := cache.accounts[uid].recheck != nil
		cache.mu.Unlock()
		if !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the released recheck did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	got, ok = cache.directory(uid, true)
	if err := strict("after the recheck", uid, "dave", got, ok); err != nil {
		t.Fatal(err)
	}
	slow("slow lookup after the resolver lifetime", func() { advance(managedHookPeerHomeTTL + time.Second) })
	if lookups.Load() != 1 {
		t.Fatalf("the unchanged account's facts were looked up %d times, want the cached ones", lookups.Load())
	}

	// An account database change: a slow lookup confirms nothing.
	waitAccount := func() {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			cache.mu.Lock()
			entry := cache.accounts[uid]
			cache.mu.Unlock()
			if entry != nil {
				select {
				case <-entry.ready:
					return
				default:
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("the released lookup did not finish")
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitAccount()
	gate := resolver.hold()
	stamp.Store("passwd-2")
	if got, ok := cache.directory(uid, true); ok {
		resolver.release(gate)
		t.Fatalf("after an account database change a slow lookup served the former facts %+v", got)
	}
	resolver.release(gate)
	waitAccount() // before the cleanup restores what the lookup reads
}
