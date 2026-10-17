// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"sync"
	"time"
)

// longNameLookupBudget bounds how long ComparisonKey waits for the 8.3 long
// name of one spelling. The lookup touches the file system, and a stalled
// redirected or network profile can hold it for good; ComparisonKey runs
// before the WinGet scan's own deadline starts and while the guardian holds
// its restore lock, so an unbounded lookup held the whole reconcile.
const longNameLookupBudget = 200 * time.Millisecond

// longNameCacheMax bounds the spellings longNameLookups remembers.
const longNameCacheMax = 256

// longNameLookups runs the long-name lookups of ComparisonKey with a bound.
// The key it gives one spelling must not change between calls: the guardian
// keeps pending restores under it across passes, and the WinGet scan slot
// is held under it until a stuck listing returns. So each spelling's first
// answer is kept: its long name when the lookup answered within the budget,
// else the spelling itself. A lookup that does not answer keeps running in
// the background (at most one per spelling) and its late answer is
// dropped. A lookup that fails fast (the path does not exist yet) is not
// kept, so a later call can still expand it.
type longNameLookups struct {
	mu      sync.Mutex
	known   map[string]string
	running map[string]bool
}

func newLongNameLookups() *longNameLookups {
	return &longNameLookups{known: map[string]string{}, running: map[string]bool{}}
}

// expand returns the long name of path from lookup and true, or "" and
// false when there is none or it did not answer within budget.
func (l *longNameLookups) expand(path string, budget time.Duration, lookup func(string) (string, bool)) (string, bool) {
	l.mu.Lock()
	if long, ok := l.known[path]; ok {
		l.mu.Unlock()
		if long == path {
			return "", false
		}
		return long, true
	}
	if l.running[path] {
		// The first lookup of this spelling has not returned or answered
		// yet; do not start a second one on the same storage.
		l.mu.Unlock()
		return "", false
	}
	l.running[path] = true
	l.mu.Unlock()

	type answer struct {
		long string
		ok   bool
	}
	answers := make(chan answer, 1)
	go func() {
		long, ok := lookup(path)
		answers <- answer{long, ok}
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case got := <-answers:
		l.mu.Lock()
		delete(l.running, path)
		if got.ok && got.long != "" {
			l.remember(path, got.long)
		}
		l.mu.Unlock()
		if !got.ok || got.long == "" {
			return "", false
		}
		return got.long, true
	case <-timer.C:
		l.mu.Lock()
		l.remember(path, path)
		l.mu.Unlock()
		go func() {
			<-answers
			l.mu.Lock()
			delete(l.running, path)
			l.mu.Unlock()
		}()
		return "", false
	}
}

// remember keeps key for path; the caller holds l.mu. A full cache keeps
// its entries, so a known spelling never changes key.
func (l *longNameLookups) remember(path, key string) {
	if _, ok := l.known[path]; ok || len(l.known) < longNameCacheMax {
		l.known[path] = key
	}
}
