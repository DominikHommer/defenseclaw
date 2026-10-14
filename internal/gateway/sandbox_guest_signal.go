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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

const (
	// A guest's first lifecycle or egress record can be delayed while it
	// starts or while the daemon retries its telemetry queue. The live lease
	// is the existing five-minute bound for that start and reporting window.
	sandboxGuestGrace       = sandboxreg.LiveLease
	sandboxGuestSignalEvery = time.Hour
	sandboxGuestSignalMax   = 4096
)

type sandboxGuestSignalKey struct {
	uid    int
	id     string
	reason string
}

type sandboxGuestSignals struct {
	mu   sync.Mutex
	last map[sandboxGuestSignalKey]time.Time
}

// sandboxGuestSignal observes one admitted route without changing its answer.
// Recorder failures are diagnostic only; a later call may retry the alert.
func (a *APIServer) sandboxGuestSignal(ctx context.Context, auth *sandboxAuthority, reg sandboxreg.Registration, reason string) {
	if !reg.GuestWatch || !reg.GuestSeenAt.IsZero() || reg.BoundAt.IsZero() || reg.SandboxName == "" ||
		reg.State == sandboxreg.StatePending || reg.State == sandboxreg.StateRevoked {
		return
	}
	now := auth.clock()
	if now.Before(reg.BoundAt.Add(sandboxGuestGrace)) {
		return
	}
	key := sandboxGuestSignalKey{uid: reg.UID, id: reg.ID, reason: reason}
	signals := &auth.guestSignals
	signals.mu.Lock()
	defer signals.mu.Unlock()
	current, ok, err := auth.store.Get(reg.UID, reg.ID)
	if err != nil {
		sandboxRecordFailed("guest signal lookup", err)
		return
	}
	if !ok || !current.GuestWatch || !current.GuestSeenAt.IsZero() || current.State == sandboxreg.StateRevoked {
		return
	}
	reg = current
	if last, ok := signals.last[key]; ok && now.Before(last.Add(sandboxGuestSignalEvery)) {
		return
	}
	identity := sandboxRecordIdentity(reg)
	if sandboxreg.EffectiveState(reg, now) == sandboxreg.StateLive {
		identity.Phase = audit.SandboxPhaseReady
	} else {
		identity.Phase = audit.SandboxPhaseStopped
	}
	if err := a.managedSandboxRecorder().RecordSandboxRegistrationWithoutGuest(context.WithoutCancel(ctx),
		audit.SandboxRegistrationWithoutGuestEvent{
			Sandbox: identity, Subject: sandboxRecordSubject(reg), Reason: reason, Timestamp: now,
		}); err != nil {
		sandboxRecordFailed("registration without guest", err)
		return
	}
	if signals.last == nil {
		signals.last = make(map[sandboxGuestSignalKey]time.Time)
	}
	for candidate, last := range signals.last {
		if !now.Before(last.Add(sandboxGuestSignalEvery)) {
			delete(signals.last, candidate)
		}
	}
	if len(signals.last) >= sandboxGuestSignalMax {
		var oldest sandboxGuestSignalKey
		var at time.Time
		for candidate, seen := range signals.last {
			if at.IsZero() || seen.Before(at) {
				oldest, at = candidate, seen
			}
		}
		delete(signals.last, oldest)
	}
	signals.last[key] = now
}

// sandboxGuestSignalGone removes a registration's rate keys when its store
// entry is revoked, removed or evicted.
func (a *APIServer) sandboxGuestSignalGone(reg sandboxreg.Registration) {
	entry, ok := sandboxAuthorities.Load(a)
	if !ok {
		return
	}
	auth := entry.(*sandboxAuthorityHolder).ready.Load()
	if auth == nil {
		return
	}
	signals := &auth.guestSignals
	signals.mu.Lock()
	defer signals.mu.Unlock()
	for key := range signals.last {
		if key.uid == reg.UID && key.id == reg.ID {
			delete(signals.last, key)
		}
	}
}

// sandboxMarkGuestSeen persists the first accepted post-bind guest record.
// Sighting failure never changes the events route's response.
func (a *APIServer) sandboxMarkGuestSeen(reg sandboxreg.Registration, at time.Time) {
	if !reg.GuestWatch || !reg.GuestSeenAt.IsZero() || reg.BoundAt.IsZero() || at.Before(reg.BoundAt) {
		return
	}
	auth, err := a.sandboxAuth()
	if err == nil {
		err = auth.store.MarkGuestSeen(reg.UID, reg.ID, at)
		if err == nil {
			a.sandboxGuestSignalGone(reg)
		}
	}
	sandboxRecordFailed("guest sighting", err)
}
