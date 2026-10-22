// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of r104 W2B G-ident, loop round 1. On a "passwd: files sss" host
// with SSSD down, a local account in a strict local group has the candidate
// of its failed or running lookup (unprovenFacts). Once 4096 other accounts
// had been looked up, room for the next candidate dropped the oldest one
// whatever its key, so the account's requests, its cache entry still
// failed (waiting for its retry) or running, had neither facts nor a
// candidate and took the lenient default_profile through
// default_lookup_failed. A candidate whose key the cache holds without facts
// is now never dropped for room; one whose key the cache serves facts for,
// or does not hold, goes first.
func TestRoomForCandidatesNeverDropsOneALookupWithoutFactsStillNeeds(t *testing.T) {
	setUnprovenFacts(t, nil)
	set, err := newGuardrailProfileSet(unprovenProfileConfig(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	prevHomes, prevLocal, prevNSS := managedHookPeerHomes, peerLocalCandidate, peerNSSFacts
	release, started := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		managedHookPeerHomes, peerLocalCandidate, peerNSSFacts = prevHomes, prevLocal, prevNSS
	})
	localFacts := func(now time.Time, groups ...string) useridentity.DirectoryFacts {
		return useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles,
			Assurance: useridentity.AssuranceVerified, ResolvedAt: now, Groups: groups}
	}
	peerLocalCandidate = func(_ int, now time.Time) (string, useridentity.DirectoryFacts, bool, error) {
		return "opsadmin", localFacts(now, "opsadmin", "strict-devs"), true, nil
	}
	peerNSSFacts = func(key string) (useridentity.DirectoryFacts, error) {
		switch key {
		case "1002": // still running
			close(started)
			<-release
		case "1003", "1004":
			return localFacts(time.Now(), "opsadmin"), nil
		}
		return useridentity.DirectoryFacts{}, errors.New("sssd: no reply")
	}
	managedHookPeerHomes = &managedHookPeerHomeCache{now: time.Now}
	cache := peerDirectoryCache()

	if _, ok := cache.get("1001", true); ok {
		t.Fatal("the failed lookup of 1001 gave facts")
	}
	go cache.get("1002", true)
	<-started
	if _, ok := cache.get("1003", true); !ok {
		t.Fatal("the lookup of 1003 gave no facts")
	}
	if _, ok := cache.get("1004", true); !ok {
		t.Fatal("the lookup of 1004 gave no facts")
	}
	// 1004's facts age out: the next request gets none.
	cache.mu.Lock()
	cache.entries["1004"].fetchedAt = time.Now().Add(-identityDirectoryMaxAge - time.Minute)
	cache.mu.Unlock()

	now := time.Now()
	held := func(key string) (unprovenFactsEntry, bool) {
		unprovenFacts.Lock()
		defer unprovenFacts.Unlock()
		entry, ok := unprovenFacts.entries[key]
		return entry, ok
	}
	failed, ok1 := held("1001")
	running, ok2 := held("1002")
	if !ok1 || !ok2 {
		t.Fatalf("no candidate for the failed (%t) or running (%t) lookup", ok1, ok2)
	}
	// A full table: the cache's keys hold the oldest candidates, 1003 (its
	// facts served) the oldest of all, then the pending ones.
	full := map[string]unprovenFactsEntry{}
	for i := 0; len(full) < identityDirectoryMax-4; i++ {
		full[strconv.Itoa(20000+i)] = localCandidate(now, "opsadmin")
	}
	full["1003"] = localCandidate(now.Add(-4*time.Minute), "opsadmin", "strict-devs")
	full["1004"] = localCandidate(now.Add(-3*time.Minute), "opsadmin", "strict-devs")
	failed.at, running.at = now.Add(-2*time.Minute), now.Add(-time.Minute)
	full["1001"], full["1002"] = failed, running
	setUnprovenFacts(t, full)
	t.Cleanup(func() { // the running lookup ends before the table is restored
		releaseOnce.Do(func() { close(release) })
		cache.explain("1002", 10*time.Second)
	})
	for i := 0; i < 4; i++ {
		noteUnprovenFacts(strconv.Itoa(30000+i), localCandidate(now, "opsadmin"), true)
	}

	unprovenFacts.Lock()
	size := len(unprovenFacts.entries)
	unprovenFacts.Unlock()
	if size != identityDirectoryMax {
		t.Fatalf("the table holds %d candidates; want %d (room is made from candidates that decide no request)", size, identityDirectoryMax)
	}
	if _, ok := held("1003"); ok {
		t.Fatal("the candidate of 1003, whose facts the cache serves, was kept while room was needed")
	}
	for _, key := range []string{"1001", "1002", "1004"} {
		if _, ok := held(key); !ok {
			t.Fatalf("the candidate of %s, whose lookup gives no facts, was dropped for room", key)
		}
	}
	for _, key := range []string{"1001", "1002"} {
		if _, ok := cache.get(key, true); ok {
			t.Fatalf("%s got facts; the case proves nothing", key)
		}
		subject := unprovenSubject(key)
		got := set.match(&subject, profileSubjectVerified, "cursor", "")
		if got.Refused == "" || got.Name != "lenient" || got.Match != profileMatchDefaultLookupFailed {
			t.Fatalf("uid %s after room was made = %+v; want refused, never the lenient default", key, got)
		}
	}
}
