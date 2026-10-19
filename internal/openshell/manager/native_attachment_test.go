// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// These tests only use the existing synthetic transaction backend. They start
// no image, namespace, child, network listener or native hook.
type nativeAttachmentProbe struct {
	*nativeTransactionBackend
	mu         sync.Mutex
	calls      int
	identity   sandboxruntime.SessionIdentity
	request    sandboxapi.AttachRequest
	entered    chan struct{}
	release    chan struct{}
	attachment *nativeAttachmentValue
}

func (p *nativeAttachmentProbe) OpenAttachment(ctx context.Context, identity sandboxruntime.SessionIdentity, request sandboxapi.AttachRequest) (sandboxruntime.Attachment, error) {
	p.mu.Lock()
	p.calls++
	p.identity, p.request = identity, request
	p.mu.Unlock()
	if p.entered != nil {
		close(p.entered)
	}
	if p.release != nil {
		select {
		case <-p.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return p.attachment, ctx.Err()
}

func (p *nativeAttachmentProbe) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

type nativeAttachmentValue struct {
	mu           sync.Mutex
	closes       int
	closeErr     error
	closeBounded bool
}

func (*nativeAttachmentValue) Send(ctx context.Context, _ sandboxapi.AttachInput) error {
	return ctx.Err()
}
func (*nativeAttachmentValue) Receive(ctx context.Context) (sandboxapi.AttachEvent, error) {
	if err := ctx.Err(); err != nil {
		return sandboxapi.AttachEvent{}, err
	}
	return sandboxapi.AttachEvent{}, io.EOF
}
func (a *nativeAttachmentValue) Close(ctx context.Context) error {
	_, bounded := ctx.Deadline()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closes++
	a.closeBounded = bounded && ctx.Err() == nil
	return a.closeErr
}

func nativeAttachmentFixture(t *testing.T) (*nativeTransactionFixture, *nativeAttachmentProbe) {
	t.Helper()
	f := nativeTransaction(t)
	p := &nativeAttachmentProbe{nativeTransactionBackend: f.b, attachment: &nativeAttachmentValue{}}
	f.m.opts.Native.backend = p
	if _, err := f.m.Create(t.Context(), f.request); err != nil {
		t.Fatal(err)
	}
	return f, p
}

func attachRequest(f *nativeTransactionFixture) sandboxapi.AttachRequest {
	return sandboxapi.AttachRequest{Version: 1, SessionID: f.m.boxes[f.request.Name].native.identity.ID, TimeoutSeconds: 30}
}

func TestNativeAttachmentUsesCompleteOwnedIdentityAndOneConsumer(t *testing.T) {
	f, p := nativeAttachmentFixture(t)
	if !f.m.AttachmentAvailable() {
		t.Fatal("owned synthetic native dependency was not offered")
	}
	request := attachRequest(f)
	wrong := request
	wrong.SessionID = "foreign-session"
	if a, err := f.m.Attach(t.Context(), f.request.Name, wrong); a != nil || err == nil || p.count() != 0 {
		t.Fatal("foreign client session reached native backend")
	}
	f.m.mu.Lock()
	f.m.boxes[f.request.Name].native.instance.Identity.Owner = "foreign-owner"
	f.m.mu.Unlock()
	if a, err := f.m.Attach(t.Context(), f.request.Name, request); a != nil || err == nil || p.count() != 0 {
		t.Fatal("changed manager-owned identity reached native backend")
	}
	f.m.mu.Lock()
	f.m.boxes[f.request.Name].native.instance.Identity.Owner = f.m.opts.Owner
	f.m.mu.Unlock()
	a, err := f.m.Attach(t.Context(), f.request.Name, request)
	if err != nil || a == nil || p.count() != 1 || p.identity != f.m.boxes[f.request.Name].native.identity || p.request != request {
		t.Fatalf("owned attachment = %v, %v; calls=%d", a, err, p.count())
	}
	if another, err := f.m.Attach(t.Context(), f.request.Name, request); another != nil || err == nil || p.count() != 1 {
		t.Fatal("same native session admitted a second consumer")
	}
	if err := a.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if p.attachment.closes != 1 || !p.attachment.closeBounded || f.m.boxes[f.request.Name].native.instance.Phase != "closed" {
		t.Fatal("attachment close did not observe bounded cleanup and stopped state")
	}
}

func TestNativeAttachmentRejectsChangedCatalogAndPublication(t *testing.T) {
	t.Run("catalog", func(t *testing.T) {
		f, p := nativeAttachmentFixture(t)
		f.b.info.Identity.Driver = "changed-driver"
		if a, err := f.m.Attach(t.Context(), f.request.Name, attachRequest(f)); a != nil || err == nil || p.count() != 0 {
			t.Fatal("changed runtime catalog reached native backend")
		}
	})
	t.Run("publication", func(t *testing.T) {
		f, p := nativeAttachmentFixture(t)
		next := sandboxruntime.PolicyAuthorityBinding{SnapshotID: "changed-outside-gate", Generation: 2}
		f.authority.Store(&next)
		if a, err := f.m.Attach(t.Context(), f.request.Name, attachRequest(f)); a != nil || err == nil || p.count() != 0 {
			t.Fatal("stale host publication reached native backend")
		}
	})
}

func TestNativeAttachmentDisconnectRetainsFailedCleanupAfterCancellation(t *testing.T) {
	f, p := nativeAttachmentFixture(t)
	a, err := f.m.Attach(t.Context(), f.request.Name, attachRequest(f))
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("synthetic native close uncertainty")
	p.attachment.closeErr = failure
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := a.Close(canceled); !errors.Is(err, failure) || p.attachment.closes != 1 || !p.attachment.closeBounded {
		t.Fatalf("canceled disconnect lost bounded native close: %v", err)
	}
	b := f.m.boxes[f.request.Name]
	if !b.native.cleanupPending || b.rec.PhaseReason == "" || p.count() != 1 {
		t.Fatal("failed attachment cleanup released or republished its reservation")
	}
	p.attachment.closeErr = nil
	if _, err := f.m.Delete(t.Context(), f.request.Name, sandboxapi.DeleteRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(f.m.boxes) != 0 || f.b.deletes != 1 {
		t.Fatal("explicit retry did not release the exact retained backend record")
	}
}

func TestNativeAttachmentAdmissionPrecedesPolicyRotation(t *testing.T) {
	f, p := nativeAttachmentFixture(t)
	p.entered, p.release = make(chan struct{}), make(chan struct{})
	request := attachRequest(f)
	result := make(chan error, 1)
	go func() {
		a, err := f.m.Attach(t.Context(), f.request.Name, request)
		if a != nil {
			err = errors.Join(err, a.Close(t.Context()))
		}
		result <- err
	}()
	<-p.entered
	published := make(chan struct{})
	rotated := make(chan error, 1)
	next := sandboxruntime.PolicyAuthorityBinding{SnapshotID: "next-native-publication", Generation: 2}
	go func() {
		rotated <- f.gate.Rotate(t.Context(), next, func(ctx context.Context) error {
			if err := f.m.RevokeNative(ctx); err != nil {
				return err
			}
			f.authority.Store(&next)
			close(published)
			return nil
		})
	}()
	select {
	case <-published:
		t.Fatal("publication passed held native attachment admission")
	case <-time.After(20 * time.Millisecond):
	}
	close(p.release)
	if err := <-rotated; err != nil {
		t.Fatal(err)
	}
	// Rotation may win the post-admission observation. Either outcome must
	// close or stop the one retained native session, never create a second.
	if err := <-result; err != nil && !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
		t.Fatalf("unexpected attachment/rotation result: %v", err)
	}
	if p.count() != 1 || f.b.stops != 1 {
		t.Fatal("rotation failed to stop the single attached native session")
	}
}
