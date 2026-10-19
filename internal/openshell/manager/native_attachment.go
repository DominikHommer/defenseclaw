// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

var (
	_ sandboxruntime.AttachController       = (*Manager)(nil)
	_ sandboxruntime.AttachmentAvailability = (*Manager)(nil)
)

// AttachmentAvailable keeps the existing OpenShell-only controller's optional
// WebSocket route closed before upgrade. The hint is never session admission.
func (m *Manager) AttachmentAvailable() bool {
	if m == nil || m.opts.Native == nil {
		return false
	}
	n := m.opts.Native
	_, supported := n.backend.(sandboxruntime.AttachmentBackend)
	if !supported || n.owner == nil || n.owner.Err() != nil || n.gate == nil {
		return false
	}
	lifetime := m.running()
	m.mu.Lock()
	closed := m.nativeClosed
	m.mu.Unlock()
	return !closed && lifetime != nil && lifetime.Err() == nil
}

// Attach claims the one consumer of the manager's already launched native
// session. The client supplies only a name and immutable ID; all policy,
// runtime and complete custody identity come from the retained owner record.
// This method never selects an OpenShell sandbox or creates a workload.
func (m *Manager) Attach(ctx context.Context, name string, request sandboxapi.AttachRequest) (sandboxruntime.Attachment, error) {
	if request.Validate() != nil {
		return nil, sandboxapi.ErrAttachProtocol
	}
	if !m.AttachmentAvailable() {
		return nil, nativeUnavailable()
	}
	m.mu.Lock()
	b := m.boxes[name]
	m.mu.Unlock()
	if b == nil || !b.op.TryLock() {
		return nil, nativeUnsupported()
	}
	defer b.op.Unlock()

	m.mu.Lock()
	n := b.native
	ready := m.boxes[name] == b && !b.deleted && !b.creating && b.phase == audit.SandboxPhaseReady &&
		n != nil && n.runtime == m.opts.Native && n.preparedComplete && !n.cleanupPending && !n.attached &&
		n.instance.Phase == "started" && n.identity.Name == name && n.instance.Identity == n.identity &&
		n.policy != nil && n.receipt.PolicyDigest == n.policy.Digest() && n.harness == b.rec.Harness &&
		request.SessionID == n.identity.ID
	if !ready {
		m.mu.Unlock()
		return nil, nativeUnsupported()
	}
	identity, harness, policy, revision := n.identity, n.harness, n.policy, n.revision
	receipt := n.receipt
	receipt.Components = slices.Clone(receipt.Components)
	m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	backend := n.runtime.backend.(sandboxruntime.AttachmentBackend)
	info, err := n.runtime.backend.Info(ctx)
	if err != nil {
		return nil, err
	}
	inner, err := n.runtime.gate.AdmitAttachment(ctx, policy, info, receipt, identity, harness, request, backend)
	m.mu.Lock()
	if m.boxes[name] == b && b.native == n {
		n.attached = true // lifetime tombstone, including a partial native admission
	}
	m.mu.Unlock()
	if inner == nil {
		if err == nil {
			return nil, nativeUnavailable()
		}
		return nil, err
	}
	a := &nativeManagedAttachment{manager: m, box: b, session: n, identity: identity, revision: revision, inner: inner}
	if err != nil {
		return nil, errors.Join(err, a.Close(ctx))
	}
	m.mu.Lock()
	stillCurrent := m.boxes[name] == b && b.native == n && !b.deleted && !m.nativeClosed &&
		!n.cleanupPending && n.revision == revision && n.instance.Phase == "started"
	m.mu.Unlock()
	if !stillCurrent || ctx.Err() != nil || n.runtime.owner.Err() != nil {
		return nil, errors.Join(nativeUnavailable(), ctx.Err(), a.Close(ctx))
	}
	return a, nil
}

// The backend owns the protocol/native worker and its exact resource record.
// This wrapper only reflects close uncertainty into the manager's retained
// reservation. Closing after cancellation uses a fresh bounded context.
type nativeManagedAttachment struct {
	manager  *Manager
	box      *box
	session  *nativeSession
	identity sandboxruntime.SessionIdentity
	revision uint64
	inner    sandboxruntime.Attachment
	once     sync.Once
	closeErr error
}

func (a *nativeManagedAttachment) Send(ctx context.Context, input sandboxapi.AttachInput) error {
	err := a.inner.Send(ctx, input)
	if err != nil {
		return errors.Join(err, a.Close(ctx))
	}
	return nil
}

func (a *nativeManagedAttachment) Receive(ctx context.Context) (sandboxapi.AttachEvent, error) {
	event, err := a.inner.Receive(ctx)
	if err != nil && !errors.Is(err, io.EOF) {
		return sandboxapi.AttachEvent{}, errors.Join(err, a.Close(ctx))
	}
	return event, err
}

func (a *nativeManagedAttachment) Close(ctx context.Context) error {
	a.once.Do(func() {
		cleanup, done := detached(ctx, 10*time.Second)
		a.closeErr = a.inner.Close(cleanup)
		done()
		m := a.manager
		m.mu.Lock()
		if b := m.boxes[a.identity.Name]; b == a.box && !b.deleted && b.native == a.session {
			n := a.session
			if a.closeErr != nil {
				n.cleanupPending = true
				b.phase = audit.SandboxPhaseError
				b.rec.PhaseReason = "native cleanup remains owned and pending"
			} else if n.revision == a.revision && !n.cleanupPending && n.instance.Phase == "started" {
				n.instance.Phase = "closed"
				b.phase = audit.SandboxPhaseStopped
				b.rec.PhaseReason = ""
			}
		}
		m.mu.Unlock()
	})
	return a.closeErr
}
