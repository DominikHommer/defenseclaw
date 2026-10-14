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

package gateway

import (
	"context"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
)

// A running managed sandbox's egress proxy decides each new connection with
// the policy the managed gateway confirmed for the sandbox's registration no
// more than sandboxEgressLease before, and confirms it again first once a
// relayed answer named another policy generation. The administrator's change
// then reaches the sandbox's first connection after the managed gateway
// applied it, tighter or looser, on every driver and platform: the daemon
// learned of it from a relayed hook or the minute's poll only, and a running
// sandbox kept the old egress lists for 20-50 s after `ensure` reported the
// new generation (a GitHub clone the new block forbids still ran; GAP-0172).
const (
	// sandboxEgressLease is how long a confirmation decides the new
	// connections of a registration's sandbox. A busy sandbox asks
	// policy/current about once a lease, well within the sandbox-policy
	// budget (10 a second per account).
	sandboxEgressLease = time.Second
	// sandboxEgressConfirmTimeout bounds one confirmation, which the
	// connection waits for.
	sandboxEgressConfirmTimeout = 2 * time.Second
)

// sandboxEgressPolicyChanging is the reason of a new connection refused
// while the sandbox's policy changed and the managed gateway has not
// confirmed the new one.
const sandboxEgressPolicyChanging = "your organization changed this sandbox's policy and DefenseClaw could not confirm the new one yet; try again in a moment"

// egressLeases are the egress leases of the daemon's registrations by id.
// The zero value is ready.
type egressLeases struct {
	mu   sync.Mutex
	byID map[string]*egressLease
}

// egressLease is one registration's: confirmed is when the last confirmation
// the managed gateway answered was asked for, tried when the last one was,
// and stale when a relayed answer last named another generation (all under
// egressLeases.mu). flight serializes the confirmations, so a burst of new
// connections asks once.
type egressLease struct {
	flight                  sync.Mutex
	confirmed, tried, stale time.Time
}

func (l *egressLeases) lease(id string) *egressLease {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byID == nil {
		l.byID = map[string]*egressLease{}
	}
	lease := l.byID[id]
	if lease == nil {
		lease = &egressLease{}
		l.byID[id] = lease
	}
	return lease
}

// expire ends id's lease: the policy changed.
func (l *egressLeases) expire(id string) {
	lease := l.lease(id)
	l.mu.Lock()
	lease.stale = time.Now()
	l.mu.Unlock()
}

// confirm records a confirmation of id asked for at sent that the managed
// gateway answered. One asked for before the policy last changed (stale)
// does not renew the lease.
func (l *egressLeases) confirm(id string, sent time.Time) {
	lease := l.lease(id)
	l.mu.Lock()
	defer l.mu.Unlock()
	if sent.After(lease.confirmed) {
		lease.confirmed = sent
	}
	if sent.After(lease.tried) {
		lease.tried = sent
	}
}

// failed records a confirmation of id asked for at sent that got no answer.
func (l *egressLeases) failed(id string, sent time.Time) {
	lease := l.lease(id)
	l.mu.Lock()
	defer l.mu.Unlock()
	if sent.After(lease.tried) {
		lease.tried = sent
	}
}

// state is lease at now: fresh (a confirmation since the last change, within
// the lease), changing (the policy changed after the last confirmation) and
// due (no confirmation was asked for since the last change and within the
// lease, so a failed one is not asked again on every connection).
func (l *egressLeases) state(lease *egressLease, now time.Time) (fresh, changing, due bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	changing = !lease.stale.IsZero() && !lease.confirmed.After(lease.stale)
	fresh = !changing && !lease.confirmed.IsZero() && now.Sub(lease.confirmed) < sandboxEgressLease
	due = lease.tried.IsZero() || now.Sub(lease.tried) >= sandboxEgressLease ||
		(changing && !lease.tried.After(lease.stale))
	return fresh, changing, due
}

// confirmEgressPolicy is the egress proxy's Refresh: it brings the policy of
// pr's sandbox up to date before a new connection of it is decided. Within
// the lease nothing is asked. Otherwise the registration's policy/current
// is, and live fields that changed have the daemon poll every registration
// at once, which adopts the floor of the running sandboxes as the minute's
// poll would and re-resolves every sandbox's policy (adoptRunningFloor):
// changed then tells the proxy to read the credential's new decider. A
// managed gateway that does not answer keeps the policy in force, as the
// poll does, unless the policy is known to have changed: then the connection
// is refused (off) until the new one is confirmed, so a tightening never
// waits for the gateway. A registration the gateway ended refuses too, and
// the poll stops its sandbox.
func (d *SandboxDaemon) confirmEgressPolicy(pr egress.Principal) (bool, *egress.Decision) {
	r, ok := d.regs.get(pr.SandboxName)
	if !ok || r.Revoked || r.ID == "" {
		return false, nil
	}
	lease := d.leases.lease(r.ID)
	if fresh, _, _ := d.leases.state(lease, time.Now()); fresh {
		return false, nil
	}
	lease.flight.Lock()
	defer lease.flight.Unlock()
	fresh, changing, due := d.leases.state(lease, time.Now())
	switch {
	case fresh:
		// A connection waiting for the same flight confirmed it.
		return false, nil
	case !due && changing:
		return false, sandboxEgressRefusal()
	case !due:
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), sandboxEgressConfirmTimeout)
	defer cancel()
	sent := time.Now()
	cp, err := d.relay.Current(ctx, r.ID)
	if _, gone := registrationGone(err); gone || (err == nil && cp.Revoked) {
		d.leases.failed(r.ID, sent)
		d.askPoll()
		return false, sandboxEgressRefusal()
	}
	if err != nil {
		d.leases.failed(r.ID, sent)
		if changing {
			d.logf("confirm the changed policy of sandbox %s: %v", r.Sandbox, err)
			return false, sandboxEgressRefusal()
		}
		return false, nil
	}
	moved := cp.Generation != 0 && cp.Generation != r.Generation
	changed := d.regs.applyLive(r.Sandbox, cp)
	d.leases.confirm(r.ID, sent)
	if !changed {
		if moved {
			// A setting outside the live fields: the managed settings and
			// the other registrations follow at once.
			d.askPoll()
		}
		return false, nil
	}
	pctx, pcancel := context.WithTimeout(context.Background(), sandboxEgressConfirmTimeout)
	defer pcancel()
	revoked := d.pollRegistrations(pctx, true)
	if len(revoked) > 0 {
		go func() {
			sctx, scancel := context.WithTimeout(context.Background(), revalidateTimeout)
			defer scancel()
			for _, rv := range revoked {
				d.stopRevoked(sctx, rv)
			}
		}()
	}
	return true, nil
}

// sandboxEgressRefusal is the refusal of a connection whose sandbox policy
// changed and is not confirmed: the organization's, egress off for now.
func sandboxEgressRefusal() *egress.Decision {
	return &egress.Decision{Category: egress.CategoryEgressOff, Source: egress.SourceAdmin, Reason: sandboxEgressPolicyChanging}
}
