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
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// freshFixture is a daemon with reg-1 for the running dc-a and a relay whose
// policy/current answer the test sets, counting the calls.
type freshFixture struct {
	*sandboxDaemonFixture
	mu     sync.Mutex
	answer sandboxrelay.CurrentPolicy
	err    error
	calls  atomic.Int32
}

func newFreshFixture(t *testing.T) *freshFixture {
	t.Helper()
	f := &freshFixture{answer: sandboxrelay.CurrentPolicy{V: 1, Generation: 7, Digest: "sha256:v1"}}
	f.sandboxDaemonFixture = newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		o.listPhases = func(context.Context) (map[string]string, bool) { return map[string]string{"dc-a": "ready"}, true }
	})
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Digest: "sha256:v1", Generation: 7,
		UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		f.calls.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.answer, f.err
	}
	return f
}

func (f *freshFixture) set(cp sandboxrelay.CurrentPolicy, err error) {
	f.mu.Lock()
	f.answer, f.err = cp, err
	f.mu.Unlock()
}

func (f *freshFixture) confirm() (bool, *egress.Decision) {
	return f.d.confirmEgressPolicy(egress.Principal{BindingID: "binding-a", SandboxName: "dc-a"})
}

func (f *freshFixture) floorBlocks(host string) bool {
	f.d.floorMu.Lock()
	defer f.d.floorMu.Unlock()
	return f.d.floor != nil && slices.Contains(f.d.floor.EgressBlock, host)
}

// GAP-0172: a running managed sandbox kept the old egress lists for 20-50 s
// after ensure reported the administrator's change (a git clone the new
// block forbids ran, a curl after the block was lifted still failed),
// because the daemon learned of the change from a relayed hook or the
// minute's poll only. Its egress proxy now confirms the sandbox's policy
// before a new connection: within a lease nothing is asked; a relayed answer
// that named another generation, or a lease that ran out (a connection no
// hook preceded, as `sandbox exec`), asks policy/current first, and a change
// re-resolves the policy (the floor the manager resolves against) before the
// connection is decided, tightened and loosened alike.
func TestSandboxDaemonEgressConfirmsTheChangedPolicyFirst(t *testing.T) {
	f := newFreshFixture(t)
	if changed, off := f.confirm(); changed || off != nil || f.calls.Load() != 1 {
		t.Fatalf("first connection: changed %v off %v calls %d", changed, off, f.calls.Load())
	}
	if changed, off := f.confirm(); changed || off != nil || f.calls.Load() != 1 {
		t.Fatalf("within the lease: changed %v off %v calls %d", changed, off, f.calls.Load())
	}

	// Tightened: the relayed hook before the clone named another generation.
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:v2",
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}, nil)
	f.d.observeGeneration("reg-1", 3)
	if changed, off := f.confirm(); !changed || off != nil {
		t.Fatalf("tightened: changed %v off %v", changed, off)
	}
	if !f.floorBlocks("github.com") {
		t.Fatalf("the floor did not take the block before the connection: %+v", f.d.floor)
	}
	if r, _ := f.d.regs.get("dc-a"); r.Generation != 3 || r.Digest != "sha256:v2" {
		t.Fatalf("registration = %+v", r)
	}
	calls := f.calls.Load()
	f.d.observeGeneration("reg-1", 3)
	if changed, off := f.confirm(); changed || off != nil || f.calls.Load() != calls {
		t.Fatalf("the same generation again: changed %v off %v calls %d -> %d", changed, off, calls, f.calls.Load())
	}

	// Loosened, under a smaller generation digest.
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 2, Digest: "sha256:v3"}, nil)
	f.d.observeGeneration("reg-1", 2)
	if changed, off := f.confirm(); !changed || off != nil || f.floorBlocks("github.com") {
		t.Fatalf("loosened: changed %v off %v floor %+v", changed, off, f.d.floor)
	}

	// No hook before the connection: the lease runs out and the connection
	// confirms the policy itself.
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 11, Digest: "sha256:v4",
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}, nil)
	time.Sleep(sandboxEgressLease + 50*time.Millisecond)
	if changed, off := f.confirm(); !changed || off != nil || !f.floorBlocks("github.com") {
		t.Fatalf("after the lease: changed %v off %v floor %+v", changed, off, f.d.floor)
	}
}

// GAP-0172: a managed gateway that does not answer keeps the policy in
// force, as the minute's poll does, unless a relayed answer already said the
// policy changed: then new connections are refused until the new policy is
// confirmed, without asking on every connection, so a tightening never waits
// for the gateway. A registration the gateway ended refuses too and asks for
// the poll that stops its sandbox.
func TestSandboxDaemonEgressRefusesAnUnconfirmedChange(t *testing.T) {
	f := newFreshFixture(t)
	f.set(sandboxrelay.CurrentPolicy{}, errors.New("dial unix: connection refused"))
	if changed, off := f.confirm(); changed || off != nil {
		t.Fatalf("no known change: changed %v off %v", changed, off)
	}
	f.d.observeGeneration("reg-1", 8)
	calls := f.calls.Load()
	for i := 0; i < 2; i++ {
		_, off := f.confirm()
		if off == nil || off.Allowed || off.Category != egress.CategoryEgressOff || off.Source != egress.SourceAdmin ||
			off.Reason != sandboxEgressPolicyChanging {
			t.Fatalf("unconfirmed change, connection %d: %+v", i, off)
		}
	}
	if f.calls.Load() != calls+1 {
		t.Fatalf("calls %d -> %d, want one try within the lease", calls, f.calls.Load())
	}

	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 8, Digest: "sha256:v1"}, nil)
	time.Sleep(sandboxEgressLease + 50*time.Millisecond)
	if _, off := f.confirm(); off != nil {
		t.Fatalf("confirmed: off %+v", off)
	}

	select {
	case <-f.d.refresh:
	default:
	}
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 8, Revoked: true, RevokedReason: "policy_changed"}, nil)
	time.Sleep(sandboxEgressLease + 50*time.Millisecond)
	if _, off := f.confirm(); off == nil || off.Category != egress.CategoryEgressOff {
		t.Fatalf("revoked: off %+v", off)
	}
	select {
	case <-f.d.refresh:
	default:
		t.Fatal("a revoked registration did not ask for the poll that stops its sandbox")
	}
}
