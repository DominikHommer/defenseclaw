// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"sync/atomic"
	"testing"
	"time"
)

// A long-name lookup that never returns must not hold the caller: the
// caller gets no long name within the budget, later calls for the spelling
// return at once with the same answer, and no second lookup starts on the
// stalled storage (B-21 review).
func TestLongNameLookupsDoNotWaitForALookupThatNeverReturns(t *testing.T) {
	lookups := newLongNameLookups()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var calls atomic.Int32
	stalled := func(string) (string, bool) {
		calls.Add(1)
		<-release
		return `C:\Users\Long Name\AppData`, true
	}
	const budget = 20 * time.Millisecond
	started := time.Now()
	if long, ok := lookups.expand(`C:\Users\LONGNA~1\AppData`, budget, stalled); ok || long != "" {
		t.Fatalf("expand = %q, %v; want no long name", long, ok)
	}
	if waited := time.Since(started); waited > 2*time.Second {
		t.Fatalf("expand waited %v for a stalled lookup", waited)
	}
	for i := 0; i < 3; i++ {
		started = time.Now()
		if long, ok := lookups.expand(`C:\Users\LONGNA~1\AppData`, budget, stalled); ok || long != "" {
			t.Fatalf("repeat expand = %q, %v; want the first answer", long, ok)
		}
		if waited := time.Since(started); waited > budget {
			t.Fatalf("repeat expand waited %v", waited)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("lookup ran %d times, want 1", got)
	}
}

// The first in-time answer of a spelling is kept, so its key does not
// change between calls; a fast failure is not kept.
func TestLongNameLookupsKeepTheFirstAnswerAndRetryAFailure(t *testing.T) {
	lookups := newLongNameLookups()
	var calls atomic.Int32
	answer := func(string) (string, bool) {
		calls.Add(1)
		return `C:\Program Files\DefenseClaw`, true
	}
	for i := 0; i < 3; i++ {
		long, ok := lookups.expand(`C:\PROGRA~1\DefenseClaw`, time.Second, answer)
		if !ok || long != `C:\Program Files\DefenseClaw` {
			t.Fatalf("expand = %q, %v", long, ok)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("answered lookup ran %d times, want 1", got)
	}
	calls.Store(0)
	missing := func(string) (string, bool) {
		calls.Add(1)
		return "", false
	}
	for i := 0; i < 2; i++ {
		if _, ok := lookups.expand(`C:\NOTYET~1`, time.Second, missing); ok {
			t.Fatal("a failed lookup gave a long name")
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("failed lookup ran %d times, want 2 (not kept)", got)
	}
}

// A spelling whose lookup timed out keeps its own spelling even after the
// late answer, so a key handed out once never changes.
func TestLongNameLookupsKeepASpellingThatTimedOut(t *testing.T) {
	lookups := newLongNameLookups()
	release := make(chan struct{})
	returned := make(chan struct{})
	late := func(string) (string, bool) {
		<-release
		defer close(returned)
		return `C:\Users\Long Name`, true
	}
	if _, ok := lookups.expand(`C:\Users\LONGNA~1`, 10*time.Millisecond, late); ok {
		t.Fatal("timed-out lookup gave a long name")
	}
	close(release)
	<-returned
	deadline := time.Now().Add(5 * time.Second)
	for {
		lookups.mu.Lock()
		running := lookups.running[`C:\Users\LONGNA~1`]
		lookups.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late lookup still marked running")
		}
		time.Sleep(time.Millisecond)
	}
	if long, ok := lookups.expand(`C:\Users\LONGNA~1`, time.Second, late); ok || long != "" {
		t.Fatalf("expand after a late answer = %q, %v; want the first answer kept", long, ok)
	}
}
