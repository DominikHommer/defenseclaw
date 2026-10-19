// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

type gateTestAttachment struct{}

func (*gateTestAttachment) Send(context.Context, sandboxapi.AttachInput) error { return nil }
func (*gateTestAttachment) Receive(context.Context) (sandboxapi.AttachEvent, error) {
	return sandboxapi.AttachEvent{}, io.EOF
}
func (*gateTestAttachment) Close(context.Context) error { return nil }

type gateTestAttachmentBackend struct {
	calls atomic.Int32
	open  func(context.Context)
}

func (b *gateTestAttachmentBackend) OpenAttachment(ctx context.Context, _ SessionIdentity, _ sandboxapi.AttachRequest) (Attachment, error) {
	b.calls.Add(1)
	if b.open != nil {
		b.open(ctx)
	}
	return &gateTestAttachment{}, nil
}

func TestLaunchGateAttachmentNeedsCurrentCompletePolicyAndIdentity(t *testing.T) {
	gate, source, policy, info, receipt, spec := launchTestInput(t)
	request := sandboxapi.AttachRequest{Version: 1, SessionID: spec.Identity.ID, TimeoutSeconds: 30}
	backend := &gateTestAttachmentBackend{}
	if _, err := gate.AdmitAttachment(t.Context(), policy, info, receipt, spec.Identity, spec.Harness, request, backend); err != nil || backend.calls.Load() != 1 {
		t.Fatalf("current owned attachment: %v, calls=%d", err, backend.calls.Load())
	}
	bad := request
	bad.SessionID = "foreign"
	if _, err := gate.AdmitAttachment(t.Context(), policy, info, receipt, spec.Identity, spec.Harness, bad, backend); err == nil || backend.calls.Load() != 1 {
		t.Fatal("foreign client ID reached backend")
	}
	changed := spec.Identity
	changed.Runtime.Driver = "foreign-driver"
	if _, err := gate.AdmitAttachment(t.Context(), policy, info, receipt, changed, spec.Harness, request, backend); err == nil || backend.calls.Load() != 1 {
		t.Fatal("changed owned identity reached backend")
	}
	missing := receipt
	missing.Components = missing.Components[1:]
	if _, err := gate.AdmitAttachment(t.Context(), policy, info, missing, spec.Identity, spec.Harness, request, backend); err == nil || backend.calls.Load() != 1 {
		t.Fatal("partial policy receipt reached backend")
	}
	next := PolicyAuthorityBinding{SnapshotID: "synthetic-outside-publisher", Generation: 2}
	source.Store(&next)
	if _, err := gate.AdmitAttachment(t.Context(), policy, info, receipt, spec.Identity, spec.Harness, request, backend); err == nil || backend.calls.Load() != 1 {
		t.Fatal("changed host authority reached backend")
	}
}

func TestLaunchGateAttachmentSerializesRotationWithNativeAdmission(t *testing.T) {
	gate, source, policy, info, receipt, spec := launchTestInput(t)
	entered, release, published := make(chan struct{}), make(chan struct{}), make(chan struct{})
	backend := &gateTestAttachmentBackend{open: func(context.Context) {
		close(entered)
		<-release
	}}
	request := sandboxapi.AttachRequest{Version: 1, SessionID: spec.Identity.ID, TimeoutSeconds: 30}
	attached := make(chan error, 1)
	go func() {
		_, err := gate.AdmitAttachment(t.Context(), policy, info, receipt, spec.Identity, spec.Harness, request, backend)
		attached <- err
	}()
	<-entered
	rotated := make(chan error, 1)
	next := PolicyAuthorityBinding{SnapshotID: "synthetic-next-publication", Generation: 2}
	go func() {
		rotated <- gate.Rotate(t.Context(), next, func(context.Context) error {
			source.Store(&next)
			close(published)
			return nil
		})
	}()
	select {
	case <-published:
		t.Fatal("publication interleaved with held attachment admission")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-attached; err != nil {
		t.Fatal(err)
	}
	if err := <-rotated; err != nil {
		t.Fatal(err)
	}
	if backend.calls.Load() != 1 {
		t.Fatal("native admission did not run exactly once")
	}
	if _, err := gate.AdmitAttachment(t.Context(), policy, info, receipt, spec.Identity, spec.Harness, request, backend); err == nil || backend.calls.Load() != 1 {
		t.Fatal("old policy attached after rotation")
	}
}
