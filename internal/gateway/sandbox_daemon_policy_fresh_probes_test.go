// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
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

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// The DELTA-15 verifier's probes for GAP-0172 (verify r1 TST-2872, verify r2
// TST-2969), kept as regression tests under their names. Each failed on
// 55054a6cd.

// V1: a connection that arrives while another one adopts the tightened
// policy takes the unlocked fast path and is admitted although the floor has
// not taken the block yet (Codex F2).
func TestVerifyD15FastPathDuringAdoption(t *testing.T) {
	f := newFreshFixture(t)
	f.confirm()
	f.d.opts.listPhases = func(context.Context) (map[string]string, bool) {
		time.Sleep(400 * time.Millisecond)
		return map[string]string{"dc-a": "ready"}, true
	}
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:v2",
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}, nil)
	f.d.observeGeneration("reg-1", 3)
	done := make(chan struct{})
	go func() { f.confirm(); close(done) }()
	time.Sleep(100 * time.Millisecond)
	changed, off := f.confirm()
	blocks := f.floorBlocks("github.com")
	<-done
	t.Logf("B: changed=%v off=%v floorBlocksAtReturn=%v", changed, off, blocks)
	if !changed && off == nil && !blocks {
		t.Errorf("BUG F2: connection B admitted with the old floor during A's adoption")
	}
}

// V1b: a connection queued on the flight lock while another connection adopts
// gets changed=false, so the proxy keeps the decider it authenticated with
// before the adoption (authenticateCurrent re-authenticates only on changed).
func TestVerifyD15WaiterKeepsPreAdoptionDecider(t *testing.T) {
	f := newFreshFixture(t)
	f.confirm()
	var slow atomic.Bool
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		f.calls.Add(1)
		if slow.Load() {
			time.Sleep(300 * time.Millisecond)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.answer, f.err
	}
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:v2",
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}, nil)
	f.d.observeGeneration("reg-1", 3)
	slow.Store(true)
	done := make(chan struct{})
	go func() { f.confirm(); close(done) }()
	time.Sleep(100 * time.Millisecond)
	blocksBefore := f.floorBlocks("github.com") // B "authenticates" now
	changed, off := f.confirm()
	blocksAfter := f.floorBlocks("github.com")
	<-done
	t.Logf("B: blocksBefore=%v changed=%v off=%v blocksAfter=%v", blocksBefore, changed, off, blocksAfter)
	if !blocksBefore && blocksAfter && !changed && off == nil {
		t.Errorf("BUG: waiter B authenticated under the old floor and refresh said unchanged, so the old decider decides it")
	}
}

// V2: a hung managed gateway serializes 2 s confirmations across a burst
// (Codex F6).
func TestVerifyD15HungGatewayBurst(t *testing.T) {
	f := newFreshFixture(t)
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		f.calls.Add(1)
		time.Sleep(sandboxEgressConfirmTimeout + 50*time.Millisecond)
		return sandboxrelay.CurrentPolicy{}, errors.New("context deadline exceeded")
	}
	var wg sync.WaitGroup
	var maxD atomic.Int64
	start := time.Now()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := time.Now()
			f.confirm()
			if d := int64(time.Since(s)); d > maxD.Load() {
				maxD.Store(d)
			}
		}()
	}
	wg.Wait()
	t.Logf("4 parallel connections, hung gateway: calls=%d slowest=%v total=%v", f.calls.Load(), time.Duration(maxD.Load()), time.Since(start))
	if f.calls.Load() > 1 {
		t.Errorf("BUG F6: %d serialized confirmations for one burst", f.calls.Load())
	}
}

// V4: the confirm path applies the new generation first, so the poll it
// asks for sees no moved generation and never reads the managed settings.
func TestVerifyD15ConfirmSkipsSettingsRefresh(t *testing.T) {
	f := newFreshFixture(t)
	var settings atomic.Int32
	f.relay.settings = func() (sandboxrelay.DaemonSettings, error) {
		settings.Add(1)
		return f.d.currentSettings(), nil
	}
	f.confirm()
	// Generation moved, live fields unchanged (a setting outside them).
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 99, Digest: "sha256:v1"}, nil)
	f.d.observeGeneration("reg-1", 99)
	changed, off := f.confirm()
	f.d.pollOnce(context.Background()) // what the asked-for poll runs
	t.Logf("changed=%v off=%v settings reads=%d", changed, off, settings.Load())
	if settings.Load() == 0 {
		t.Errorf("BUG: a generation the confirm path saw first never refreshed the managed settings")
	}
	// Same through the live-field change path.
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 5, Digest: "sha256:v9",
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}, nil)
	f.d.observeGeneration("reg-1", 5)
	before := settings.Load()
	changed, off = f.confirm()
	t.Logf("live change: changed=%v off=%v settings reads %d -> %d", changed, off, before, settings.Load())
	if settings.Load() == before {
		t.Errorf("BUG: a live-field change seen by confirm never refreshed the managed settings")
	}
}

// V5: an old poll reply applied after the confirm path adopted the new
// block rolls it back (Codex F3). The registration's requests now take
// turns, so the confirmation waits for the poll's open request and asks
// after it: every connection after the change is either refused or decided
// with the block, and the old reply never undoes it.
func TestVerifyD15OldPollRollback(t *testing.T) {
	f := newFreshFixture(t)
	f.confirm()
	oldA := sandboxrelay.CurrentPolicy{V: 1, Generation: 7, Digest: "sha256:v1"}
	newA := sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:v2",
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}
	release := make(chan struct{})
	var n atomic.Int32
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		if n.Add(1) == 1 {
			<-release
			return oldA, nil
		}
		return newA, nil
	}
	pollDone := make(chan struct{})
	go func() { f.d.pollRegistrations(context.Background(), true); close(pollDone) }()
	time.Sleep(50 * time.Millisecond)
	f.d.observeGeneration("reg-1", 3)
	type outcome struct {
		changed bool
		off     *egress.Decision
		blocks  bool
	}
	first := make(chan outcome, 1)
	go func() {
		c, off := f.confirm()
		first <- outcome{c, off, f.floorBlocks("github.com")}
	}()
	time.Sleep(50 * time.Millisecond)
	if got := n.Load(); got != 1 {
		t.Errorf("BUG F3: the confirmation asked (%d requests) while the poll's older request was still open", got)
	}
	close(release)
	<-pollDone
	c1 := <-first
	afterOld := f.floorBlocks("github.com")
	c2, off2 := f.confirm() // within lease
	withinLease := f.floorBlocks("github.com")
	time.Sleep(sandboxEgressLease + 50*time.Millisecond)
	c3, off3 := f.confirm()
	afterLease := f.floorBlocks("github.com")
	t.Logf("confirm changed=%v off=%v blocks=%v; after old poll blocks=%v; within lease changed=%v off=%v blocks=%v; after lease changed=%v off=%v blocks=%v",
		c1.changed, c1.off, c1.blocks, afterOld, c2, off2, withinLease, c3, off3, afterLease)
	if c1.off == nil && !c1.blocks {
		t.Errorf("BUG: the connection after the change was decided with the old floor")
	}
	if c1.blocks && !afterOld {
		t.Errorf("BUG F3: the old poll reply rolled back the adopted block (restored after lease: %v)", afterLease)
	}
	if (off2 == nil && !withinLease) || (off3 == nil && !afterLease) {
		t.Errorf("BUG: a later connection was decided with the old floor")
	}
}

// R2-P1: the supervise loop's poll (what observeGeneration's askPoll runs)
// renews reg-1's egress lease in its loop, before adoptRunningFloor. A
// connection of dc-a that arrives while the poll still waits on another
// registration's policy/current takes the unlocked fast path and is decided
// under the floor that does not have the new block yet.
func TestVerifyR2PollRenewsLeaseBeforeAdoption(t *testing.T) {
	f := newFreshFixture(t)
	f.d.opts.listPhases = func(context.Context) (map[string]string, bool) {
		return map[string]string{"dc-a": "ready", "dc-b": "ready"}, true
	}
	if err := f.d.regs.put(daemonRegistration{ID: "reg-2", Sandbox: "dc-b", Digest: "sha256:v1", Generation: 7,
		UpdatedAt: time.Now().Add(-time.Hour), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	f.confirm()
	newA := sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:v2", UpdatedAt: time.Now(),
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}
	oldB := sandboxrelay.CurrentPolicy{V: 1, Generation: 7, Digest: "sha256:v1", UpdatedAt: time.Now().Add(-time.Hour)}
	release := make(chan struct{})
	f.relay.current = func(id string) (sandboxrelay.CurrentPolicy, error) {
		f.calls.Add(1)
		if id == "reg-2" {
			<-release
			return oldB, nil
		}
		return newA, nil
	}
	f.d.observeGeneration("reg-1", 3)
	pollDone := make(chan struct{})
	go func() { f.d.pollRegistrations(context.Background(), true); close(pollDone) }()
	time.Sleep(150 * time.Millisecond)
	calls := f.calls.Load()
	changed, off := f.confirm()
	blocks := f.floorBlocks("github.com")
	asked := f.calls.Load() - calls
	close(release)
	<-pollDone
	t.Logf("during poll: changed=%v off=%v floorBlocks=%v extraCurrentCalls=%d; after poll floorBlocks=%v",
		changed, off, blocks, asked, f.floorBlocks("github.com"))
	if !changed && off == nil && !blocks {
		t.Errorf("BUG: the poll renewed the lease before the adoption; the connection is decided by the old floor")
	}
}
