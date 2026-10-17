//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// directoryReturnScript drives enterpriseHookWatchDirectoryReturn: each poll
// reads the next step (are the caches stale, does the domain controller
// answer), and the clock moves one poll per sleep.
type directoryReturnScript struct {
	steps   []struct{ stale, answers bool }
	at      int
	now     time.Time
	flushes []int
	asked   int
}

func (s *directoryReturnScript) deps() enterpriseHookDirectoryReturnDeps {
	return enterpriseHookDirectoryReturnDeps{
		stale: func(string, []enterprisehooks.IdentitySpoolAccount) (string, bool) {
			if s.at >= len(s.steps) {
				return "", false
			}
			return "dclab.test", s.steps[s.at].stale
		},
		answers: func(_ context.Context, domain string) bool {
			s.asked++
			return domain == "dclab.test" && s.steps[s.at].answers
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
	state.watching, state.lastFlush, state.gap = false, time.Time{}, 0
	state.Unlock()
	t.Cleanup(func() {
		state.Lock()
		state.watching, state.lastFlush, state.gap = false, time.Time{}, 0
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
		s.steps = append(s.steps, struct{ stale, answers bool }{true, false})
	}
	// Back: one poll still stale (the flush), then the groups are listed.
	s.steps = append(s.steps, struct{ stale, answers bool }{true, true}, struct{ stale, answers bool }{false, true})
	var stderr bytes.Buffer
	enterpriseHookWatchDirectoryReturn(context.Background(), &stderr, s.deps(), "", []enterprisehooks.IdentitySpoolAccount{{UID: 501}})
	if len(s.flushes) != 1 || s.flushes[0] != 8 {
		t.Fatalf("flushes at polls %v, want one at poll 8 (the domain controller's return)", s.flushes)
	}
	if s.asked != 9 {
		t.Fatalf("asked the domain controller %d times, want once per stale poll", s.asked)
	}
	if !strings.Contains(stderr.String(), "a domain controller of dclab.test answers again") {
		t.Fatalf("log = %q", stderr.String())
	}
	if state := &enterpriseHookDirectoryReturnState; state.gap != 0 {
		t.Fatalf("the backoff was not reset once the groups were listed: %s", state.gap)
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
		s.steps = append(s.steps, struct{ stale, answers bool }{true, true})
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
	healthy.steps = append(healthy.steps, struct{ stale, answers bool }{false, true})
	enterpriseHookWatchDirectoryReturn(context.Background(), &bytes.Buffer{}, healthy.deps(), "", []enterprisehooks.IdentitySpoolAccount{{UID: 501}})
	if healthy.asked != 0 || len(healthy.flushes) != 0 {
		t.Fatalf("healthy caches: asked %d, flushed %v", healthy.asked, healthy.flushes)
	}
}
