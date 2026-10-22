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

package observability

import (
	"context"
	"sync"
)

type remoteDeliveryKey struct{}

// RemoteDelivery follows the optional-destination deliveries of one
// occurrence that its producer keeps durably queued under a stable id (a
// trust anchor or credential change event) and offers until every
// destination has it. The producer keeps one RemoteDelivery per occurrence
// across offers: each offer is an attempt, a destination that acknowledged
// an earlier attempt is not sent the occurrence again, and the occurrence
// is delivered once an attempt ends with no destination left to fail. A
// producer that keeps the acknowledgements on disk
// (NewRecordedRemoteDelivery) does not send the occurrence again to those
// destinations after a restart; otherwise the state is in memory only.
type RemoteDelivery struct {
	mu       sync.Mutex
	attempt  uint64
	open     bool
	inFlight int
	// failed is set when a destination of the current attempt did not
	// get the occurrence.
	failed    bool
	delivered map[string]bool
	// localDurable records that the local store made the occurrence
	// power-loss durable, so a later offer need not flush it again.
	localDurable bool
	// record, if set, keeps a destination's acknowledgement on disk.
	record func(destination string)
}

// NewRemoteDelivery returns the delivery state of one occurrence.
func NewRemoteDelivery() *RemoteDelivery {
	return &RemoteDelivery{delivered: make(map[string]bool)}
}

// NewRecordedRemoteDelivery returns the delivery state of one occurrence
// whose acknowledged destinations were recorded by an earlier process.
// record is called with each destination that acknowledges it, before the
// acknowledgement counts, so a restart between the acknowledgement and the
// producer's next offer does not send the occurrence to it again.
func NewRecordedRemoteDelivery(acknowledged []string, record func(destination string)) *RemoteDelivery {
	delivery := NewRemoteDelivery()
	for _, destination := range acknowledged {
		delivery.delivered[destination] = true
	}
	delivery.record = record
	return delivery
}

// WithRemoteDelivery attaches delivery to ctx, so the runtime reports every
// optional-destination outcome of the occurrence emitted with ctx to it.
func WithRemoteDelivery(ctx context.Context, delivery *RemoteDelivery) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if delivery == nil {
		return ctx
	}
	return context.WithValue(ctx, remoteDeliveryKey{}, delivery)
}

// RemoteDeliveryFrom returns the RemoteDelivery attached to ctx, or nil.
func RemoteDeliveryFrom(ctx context.Context) *RemoteDelivery {
	if ctx == nil {
		return nil
	}
	delivery, _ := ctx.Value(remoteDeliveryKey{}).(*RemoteDelivery)
	return delivery
}

// BeginAttempt starts an offer: failures of an earlier attempt are
// forgotten, destinations that acknowledged are kept.
func (delivery *RemoteDelivery) BeginAttempt() {
	if delivery == nil {
		return
	}
	delivery.mu.Lock()
	defer delivery.mu.Unlock()
	delivery.attempt++
	delivery.open, delivery.failed = true, false
}

// EndAttempt ends the emission of an offer. Deliveries it handed to
// destinations may still be in flight.
func (delivery *RemoteDelivery) EndAttempt() {
	if delivery == nil {
		return
	}
	delivery.mu.Lock()
	delivery.open = false
	delivery.mu.Unlock()
}

// Acknowledged reports whether destination acknowledged an earlier attempt.
func (delivery *RemoteDelivery) Acknowledged(destination string) bool {
	if delivery == nil {
		return false
	}
	delivery.mu.Lock()
	defer delivery.mu.Unlock()
	return delivery.delivered[destination]
}

// Fail records that destination did not get the occurrence in this attempt
// (it could not be projected or queued).
func (delivery *RemoteDelivery) Fail(destination string) {
	if delivery == nil {
		return
	}
	delivery.mu.Lock()
	defer delivery.mu.Unlock()
	if !delivery.delivered[destination] {
		delivery.failed = true
	}
}

// Track records one delivery handed to destination and returns the function
// its queue calls once with the terminal outcome: delivered when the
// destination acknowledged it, false when it was refused, dropped or
// abandoned. Later calls are ignored.
func (delivery *RemoteDelivery) Track(destination string) func(delivered bool) {
	if delivery == nil {
		return func(bool) {}
	}
	delivery.mu.Lock()
	delivery.inFlight++
	attempt := delivery.attempt
	delivery.mu.Unlock()
	var once sync.Once
	return func(delivered bool) {
		once.Do(func() {
			if delivered && delivery.record != nil {
				delivery.record(destination)
			}
			delivery.mu.Lock()
			defer delivery.mu.Unlock()
			delivery.inFlight--
			if delivered {
				delivery.delivered[destination] = true
			} else if attempt == delivery.attempt && !delivery.delivered[destination] {
				delivery.failed = true
			}
		})
	}
}

// Settled reports whether the last attempt has ended with nothing in
// flight, and if so whether every destination of it has the occurrence.
// Nothing to deliver (a nil RemoteDelivery, an occurrence no destination
// takes) is delivered.
func (delivery *RemoteDelivery) Settled() (settled, delivered bool) {
	if delivery == nil {
		return true, true
	}
	delivery.mu.Lock()
	defer delivery.mu.Unlock()
	if delivery.open || delivery.inFlight > 0 {
		return false, false
	}
	return true, !delivery.failed
}

// MarkLocalDurable records that the local store holds the occurrence in a
// form that survives a power loss.
func (delivery *RemoteDelivery) MarkLocalDurable() {
	if delivery == nil {
		return
	}
	delivery.mu.Lock()
	delivery.localDurable = true
	delivery.mu.Unlock()
}

// LocalDurable reports whether MarkLocalDurable was called.
func (delivery *RemoteDelivery) LocalDurable() bool {
	if delivery == nil {
		return false
	}
	delivery.mu.Lock()
	defer delivery.mu.Unlock()
	return delivery.localDurable
}
