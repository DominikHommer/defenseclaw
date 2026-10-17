// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// listedAccounts is a local account list the fake source digests.
type listedAccounts struct {
	mu       sync.Mutex
	accounts map[string]int
	calls    int
	fail     bool
	gate     chan struct{} // when set, a listing waits on it
}

func (l *listedAccounts) set(accounts map[string]int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.accounts = accounts
}

func (l *listedAccounts) list() (string, error) {
	l.mu.Lock()
	l.calls++
	gate, fail := l.gate, l.fail
	accounts := make(map[string]int, len(l.accounts))
	for name, uid := range l.accounts {
		accounts[name] = uid
	}
	l.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if fail {
		return "", errors.New("dscl failed")
	}
	return localAccountsDigest(accounts)
}

func unreadableStat() string { return "" }

func waitListed(t *testing.T, s *managedHookPeerAccountsSource) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		done := !s.refreshing
		s.mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("background listing did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLocalAccountsDigestIsOrderFreeAndSeesNameAndUID(t *testing.T) {
	a, err := localAccountsDigest(map[string]int{"alice": 501, "bob": 502})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := localAccountsDigest(map[string]int{"bob": 502, "alice": 501}); a != b {
		t.Fatalf("digest depends on order: %q %q", a, b)
	}
	for _, changed := range []map[string]int{{"alice": 503, "bob": 502}, {"alicf": 501, "bob": 502}, {"alice": 501}} {
		if b, _ := localAccountsDigest(changed); b == a {
			t.Fatalf("digest unchanged for %v", changed)
		}
	}
	if _, err := localAccountsDigest(nil); err == nil {
		t.Fatal("an empty list has a digest")
	}
}

func TestAccountsSourcePrefersTheReadableFile(t *testing.T) {
	listing := &listedAccounts{accounts: map[string]int{"alice": 501}}
	s := &managedHookPeerAccountsSource{stat: func() string { return "file" }, list: listing.list, now: time.Now}
	s.refresh()
	if got := s.get(); got != "file" || listing.calls != 0 {
		t.Fatalf("get = %q after %d listings, want the file stamp and none", got, listing.calls)
	}
	if got := (&managedHookPeerAccountsSource{stat: unreadableStat, now: time.Now}).get(); got != "" {
		t.Fatalf("no source = %q, want empty", got)
	}
}

// GAP-0669: on macOS the service account cannot read the dslocal users
// directory, so the stamp was always "" there.
func TestAccountsSourceListsWhenTheFileIsUnreadable(t *testing.T) {
	listing := &listedAccounts{accounts: map[string]int{"alice": 501}}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	s := &managedHookPeerAccountsSource{stat: unreadableStat, list: listing.list, now: func() time.Time { return time.Unix(0, clock.Load()) }}
	s.get() // a request never waits for the first listing
	waitListed(t, s)
	before := s.get()
	if before == "" {
		t.Fatal("no listed stamp after the first listing")
	}
	listing.set(map[string]int{"alice": 502})
	if got := s.get(); got != before {
		t.Fatalf("a request listed again inside the interval: %q", got)
	}
	clock.Add(int64(managedHookPeerListedStampInterval))
	s.get()
	waitListed(t, s)
	after := s.get()
	if after == before || after == "" {
		t.Fatalf("stamp after the interval = %q, before %q", after, before)
	}
	listing.set(map[string]int{"alice": 503})
	s.refresh() // explain: at once
	if got := s.get(); got == after || got == "" {
		t.Fatalf("refresh did not list at once: %q", got)
	}
	listing.mu.Lock()
	listing.fail = true
	listing.mu.Unlock()
	s.refresh()
	if got := s.get(); got != "" {
		t.Fatalf("a failed listing kept a stamp: %q", got)
	}
}

// A slow background listing that started before a change must not put
// back the stamp from before it over the one explain listed after it.
func TestAccountsSourceKeepsTheLaterListing(t *testing.T) {
	gate := make(chan struct{})
	listing := &listedAccounts{accounts: map[string]int{"alice": 501}, gate: gate}
	s := &managedHookPeerAccountsSource{stat: unreadableStat, list: listing.list, now: time.Now}
	s.get() // starts a listing that waits on the gate
	for {
		listing.mu.Lock()
		started := listing.calls == 1
		listing.mu.Unlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	listing.mu.Lock()
	listing.accounts, listing.gate = map[string]int{"alice": 502}, nil
	listing.mu.Unlock()
	s.refresh()
	want, _ := localAccountsDigest(map[string]int{"alice": 502})
	if got := s.get(); got != want {
		t.Fatalf("after refresh = %q, want %q", got, want)
	}
	close(gate) // the first listing ends now, with the old accounts
	waitListed(t, s)
	if got := s.get(); got != want {
		t.Fatalf("the older listing replaced the later one: %q", got)
	}
}

// GAP-0669: with only the listed stamp, explain by the name of a removed
// local account recreated with a new uid resolves the live account alone.
func TestL1ListedStampDropsRemovedNamesakeAtOnce(t *testing.T) {
	const oldUID, liveUID = 94101, 94102
	old := unixidentity.Account{Name: "alice", UID: oldUID, Home: "/Users/Shared/alice"}
	live := unixidentity.Account{Name: "alice", UID: liveUID, Home: "/Users/Shared/alice"}
	resolver := &changingHolderAccounts{accounts: map[int]unixidentity.Account{oldUID: old}}
	listing := &listedAccounts{accounts: map[string]int{"alice": oldUID}}
	now := time.Now
	previous, enabled, source := managedHookPeerHomes, identityFactsEnabled.Load(), managedHookPeerAccounts
	previousManaged := ManagedEnterpriseActive()
	managedHookPeerAccounts = &managedHookPeerAccountsSource{stat: unreadableStat, list: listing.list, now: now}
	managedHookPeerHomes = holderTestCache(t, resolver, useridentity.DirectoryLocal, now)
	setIdentityFactsEnabled(true)
	SetManagedEnterpriseActive(false)
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookPeerAccounts = previous, source
		setIdentityFactsEnabled(enabled)
		SetManagedEnterpriseActive(previousManaged)
	})
	managedHookPeerAccountsRefresh()
	if _, err := managedHookPeerHomes.explainDirectory(oldUID); err != nil {
		t.Fatal(err)
	}
	delete(resolver.accounts, oldUID)
	resolver.accounts[liveUID] = live
	listing.set(map[string]int{"alice": liveUID})
	if twins := sameNameProfileAccounts(context.Background(), resolver, "alice", live); len(twins) != 0 {
		t.Fatalf("bare name alice names the removed uid too: %+v", twins)
	}
	if uid, _, ok := managedHookPeerHomes.cachedHolder("alice"); ok {
		t.Fatalf("removed alice is still a cached subject at uid %d", uid)
	}
}
