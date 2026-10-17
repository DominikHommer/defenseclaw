//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// directoryReturnPoll is one poll of a directoryReturnScript: for each
// domain, whether the caches list one of its accounts without groups, and
// whether one of its domain controllers answers.
type directoryReturnPoll map[string]struct{ stale, answers bool }

// oneDomain is a poll of the single domain dclab.test.
func oneDomain(stale, answers bool) directoryReturnPoll {
	return directoryReturnPoll{"dclab.test": {stale, answers}}
}

// directoryReturnScript drives enterpriseHookWatchDirectoryReturn: each poll
// reads the next step, and the clock moves one poll per sleep.
type directoryReturnScript struct {
	mu      sync.Mutex
	steps   []directoryReturnPoll
	at      int
	now     time.Time
	flushes []int
	asked   map[string]int
}

func (s *directoryReturnScript) deps() enterpriseHookDirectoryReturnDeps {
	return enterpriseHookDirectoryReturnDeps{
		stale: func(string, []enterprisehooks.IdentitySpoolAccount) []string {
			if s.at >= len(s.steps) {
				return nil
			}
			var domains []string
			for domain, step := range s.steps[s.at] {
				if step.stale {
					domains = append(domains, domain)
				}
			}
			slices.Sort(domains)
			return domains
		},
		answers: func(_ context.Context, domain string) bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.asked == nil {
				s.asked = map[string]int{}
			}
			s.asked[domain]++
			return s.steps[s.at][domain].answers
		},
		flush: func(context.Context) error { s.flushes = append(s.flushes, s.at); return nil },
		now:   func() time.Time { return s.now },
		sleep: func(context.Context, time.Duration) bool {
			s.at++
			s.now = s.now.Add(enterpriseHookDirectoryReturnPoll)
			return true
		},
	}
}

func resetDirectoryReturnState(t *testing.T) {
	t.Helper()
	state := &enterpriseHookDirectoryReturnState
	state.Lock()
	state.watching, state.flushed = false, nil
	state.Unlock()
	t.Cleanup(func() {
		state.Lock()
		state.watching, state.flushed = false, nil
		state.Unlock()
	})
}

// #1197, GAP-0680, GAP-0517: after a directory outage a bound Mac kept
// answering from Open Directory's caches (accounts without their domain
// groups) for 11 to 19 minutes, and the accounts stayed on the offline floor
// until a manual flush. The guardian's old trigger, a pass that resolved
// accounts after one that resolved none, flushed once during the outage
// (local and mobile accounts resolve then too) and never after it. Now the
// caches are flushed when the domain controller answers while they still
// list an account without its groups, within one poll of its return, and
// never while it does not answer.
func TestDirectoryReturnFlushesOnceTheDomainControllerAnswers(t *testing.T) {
	resetDirectoryReturnState(t)
	s := &directoryReturnScript{now: time.Unix(1_800_000_000, 0)}
	for range 8 {
		// The outage: the caches lack the groups, the domain controller is away.
		s.steps = append(s.steps, oneDomain(true, false))
	}
	// Back: one poll still stale (the flush), then the groups are listed.
	s.steps = append(s.steps, oneDomain(true, true), oneDomain(false, true))
	var stderr bytes.Buffer
	enterpriseHookWatchDirectoryReturn(context.Background(), &stderr, s.deps(), "", []enterprisehooks.IdentitySpoolAccount{{UID: 501}})
	if len(s.flushes) != 1 || s.flushes[0] != 8 {
		t.Fatalf("flushes at polls %v, want one at poll 8 (the domain controller's return)", s.flushes)
	}
	if s.asked["dclab.test"] != 9 {
		t.Fatalf("asked the domain controller %d times, want once per stale poll", s.asked["dclab.test"])
	}
	if !strings.Contains(stderr.String(), "a domain controller of dclab.test answers again") {
		t.Fatalf("log = %q", stderr.String())
	}
	if state := &enterpriseHookDirectoryReturnState; len(state.flushed) != 0 {
		t.Fatalf("the backoff was not reset once the groups were listed: %v", state.flushed)
	}
}

// A flush that does not clear the stale answers (an account the directory
// lists without groups for another reason) is repeated with a growing gap,
// not every poll; caches that never lacked the groups ask nobody.
func TestDirectoryReturnBacksOffAndAsksOnlyWhileStale(t *testing.T) {
	resetDirectoryReturnState(t)
	s := &directoryReturnScript{now: time.Unix(1_800_000_000, 0)}
	polls := int(enterpriseHookDirectoryWatchLimit / enterpriseHookDirectoryReturnPoll)
	for range polls + 5 {
		s.steps = append(s.steps, oneDomain(true, true))
	}
	enterpriseHookWatchDirectoryReturn(context.Background(), &bytes.Buffer{}, s.deps(), "", []enterprisehooks.IdentitySpoolAccount{{UID: 501}})
	// At once, then 2 and 4 more minutes later; the next (8 minutes on)
	// falls past the 10-minute watch.
	if got := s.flushes; len(got) != 3 || got[0] != 0 || got[1] != 8 || got[2] != 24 {
		t.Fatalf("flushes at polls %v, want 0, 8 and 24", got)
	}
	if s.at > polls {
		t.Fatalf("the watch ran %d polls, past its limit of %d", s.at, polls)
	}

	resetDirectoryReturnState(t)
	healthy := &directoryReturnScript{now: time.Unix(1_800_000_000, 0)}
	healthy.steps = append(healthy.steps, oneDomain(false, true))
	enterpriseHookWatchDirectoryReturn(context.Background(), &bytes.Buffer{}, healthy.deps(), "", []enterprisehooks.IdentitySpoolAccount{{UID: 501}})
	if len(healthy.asked) != 0 || len(healthy.flushes) != 0 {
		t.Fatalf("healthy caches: asked %v, flushed %v", healthy.asked, healthy.flushes)
	}
}

// #1197 review: a Mac with enrolled accounts in two Active Directory
// domains. The watch asked only the first stale domain's domain controllers,
// so while that domain stayed away the other's accounts stayed on the
// offline floor after their domain controller was back; and one flush
// backoff for all domains let the second domain's flush delay the first's by
// two minutes. Each domain is now asked every poll it is stale and backed
// off on its own: each recovers within one poll of its own return.
func TestDirectoryReturnRecoversEachDomainOnItsOwn(t *testing.T) {
	resetDirectoryReturnState(t)
	s := &directoryReturnScript{now: time.Unix(1_800_000_000, 0)}
	type st = struct{ stale, answers bool }
	away, back := st{true, false}, st{true, true}
	for range 4 {
		// Both domains away; a.test sorts first.
		s.steps = append(s.steps, directoryReturnPoll{"a.test": away, "b.test": away})
	}
	s.steps = append(s.steps,
		// Poll 4: b.test is back while a.test is still away; flush for b.test.
		directoryReturnPoll{"a.test": away, "b.test": back},
		// Poll 5: b.test's accounts not yet cleared, within its backoff: not
		// asked again; a.test still away.
		directoryReturnPoll{"a.test": away, "b.test": back},
		// Poll 6: a.test is back 30 seconds after b.test's flush: its own
		// flush is not held by b.test's backoff.
		directoryReturnPoll{"a.test": back, "b.test": back},
		// Poll 7: every account lists its groups.
		directoryReturnPoll{"a.test": {false, true}, "b.test": {false, true}},
	)
	var stderr bytes.Buffer
	enterpriseHookWatchDirectoryReturn(context.Background(), &stderr, s.deps(), "", []enterprisehooks.IdentitySpoolAccount{{UID: 94401103}, {UID: 94401105}})
	if !slices.Equal(s.flushes, []int{4, 6}) {
		t.Fatalf("flushes at polls %v, want 4 (b.test back) and 6 (a.test back)", s.flushes)
	}
	if s.asked["a.test"] != 7 || s.asked["b.test"] != 5 {
		t.Fatalf("asked a.test %d and b.test %d times, want 7 (every stale poll) and 5 (until its flush)", s.asked["a.test"], s.asked["b.test"])
	}
	log := stderr.String()
	if !strings.Contains(log, "a domain controller of b.test answers again") || !strings.Contains(log, "a domain controller of a.test answers again") ||
		strings.Count(log, "answers again") != 2 {
		t.Fatalf("log = %q, want one line for each domain's return", log)
	}
	if state := &enterpriseHookDirectoryReturnState; len(state.flushed) != 0 {
		t.Fatalf("the backoff was not reset once the groups were listed: %v", state.flushed)
	}
}
