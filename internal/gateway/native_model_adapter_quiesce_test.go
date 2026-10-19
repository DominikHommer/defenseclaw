// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"
)

type nativeModelSlowCommitWriter struct {
	*nativeModelCommitWriter
	entered chan struct{}
	release chan struct{}
}

func (writer *nativeModelSlowCommitWriter) Write(data []byte) (int, error) {
	close(writer.entered)
	<-writer.release
	return writer.nativeModelCommitWriter.Write(data)
}

func TestNativeModelAdapterSealQuiescesCurrentWrite(t *testing.T) {
	adapter, _, _, _ := nativeModelFixture(t)
	sink := &nativeModelSlowCommitWriter{nativeModelCommitWriter: &nativeModelCommitWriter{header: make(http.Header)},
		entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(sink.release) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &nativeModelWriter{adapter: adapter, ctx: ctx, target: sink,
		header: make(http.Header), cancel: cancel, wrote: true}
	writeResult := make(chan any, 1)
	go func() {
		defer func() { writeResult <- recover() }()
		_, _ = writer.Write([]byte("first"))
	}()
	select {
	case <-sink.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("downstream write did not enter")
	}
	quiesced := make(chan error, 1)
	go func() {
		wait, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		quiesced <- adapter.SealAndQuiesce(wait)
	}()
	select {
	case <-adapter.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("adapter did not seal")
	}
	select {
	case err := <-quiesced:
		t.Fatalf("quiesced before current downstream write finished: %v", err)
	default:
	}
	for _, commit := range []func(*nativeModelWriter){
		func(w *nativeModelWriter) { w.WriteHeader(http.StatusOK) },
		func(w *nativeModelWriter) { _, _ = w.Write([]byte("late")) },
		func(w *nativeModelWriter) { w.Flush() },
	} {
		otherCtx, otherCancel := context.WithCancel(context.Background())
		other := &nativeModelWriter{adapter: adapter, ctx: otherCtx, target: sink,
			header: make(http.Header), cancel: otherCancel, wrote: true}
		nativeModelExpectAbort(t, func() { commit(other) })
		otherCancel()
	}
	release.Do(func() { close(sink.release) })
	select {
	case got := <-writeResult:
		if got != nil {
			t.Fatalf("already admitted write panicked: %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("admitted write did not finish")
	}
	select {
	case err := <-quiesced:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("quiescence did not finish after writer release")
	}
	if sink.body.String() != "first" || sink.flushes != 0 {
		t.Fatal("sealed writer admitted later body or flush output")
	}
}

func TestNativeModelAdapterQuiesceDeadlineRetainsSeal(t *testing.T) {
	adapter, _, _, _ := nativeModelFixture(t)
	sink := &nativeModelSlowCommitWriter{nativeModelCommitWriter: &nativeModelCommitWriter{header: make(http.Header)},
		entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(sink.release) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &nativeModelWriter{adapter: adapter, ctx: ctx, target: sink,
		header: make(http.Header), cancel: cancel, wrote: true}
	finished := make(chan struct{})
	go func() { defer close(finished); _, _ = writer.Write([]byte("first")) }()
	select {
	case <-sink.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("downstream write did not enter")
	}
	deadline, done := context.WithCancel(context.Background())
	done()
	if err := adapter.SealAndQuiesce(deadline); err == nil {
		t.Fatal("canceled quiescence unexpectedly succeeded with active write")
	}
	lateCtx, lateCancel := context.WithCancel(context.Background())
	defer lateCancel()
	late := &nativeModelWriter{adapter: adapter, ctx: lateCtx, target: sink,
		header: make(http.Header), cancel: lateCancel, wrote: true}
	nativeModelExpectAbort(t, func() { _, _ = late.Write([]byte("late")) })
	release.Do(func() { close(sink.release) })
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("retained downstream write did not finish")
	}
	retry, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := adapter.SealAndQuiesce(retry); err != nil {
		t.Fatalf("sealed owner could not quiesce on retry: %v", err)
	}
}

type nativeModelPanicCommitWriter struct{ *nativeModelCommitWriter }

func (*nativeModelPanicCommitWriter) Write([]byte) (int, error) { panic("fixed downstream panic") }

func TestNativeModelAdapterCommitPanicReleasesClaim(t *testing.T) {
	adapter, _, _, _ := nativeModelFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := &nativeModelPanicCommitWriter{&nativeModelCommitWriter{header: make(http.Header)}}
	writer := &nativeModelWriter{adapter: adapter, ctx: ctx, target: sink,
		header: make(http.Header), cancel: cancel, wrote: true}
	var got any
	func() {
		defer func() { got = recover() }()
		_, _ = writer.Write([]byte("first"))
	}()
	if got != "fixed downstream panic" {
		t.Fatalf("unexpected downstream panic: %v", got)
	}
	wait, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if err := adapter.SealAndQuiesce(wait); err != nil {
		t.Fatalf("panic leaked downstream claim: %v", err)
	}
}

func TestNativeModelAdapterQuiesceDoesNotWaitForInspection(t *testing.T) {
	adapter, _, _, inspector := nativeModelFixture(t)
	gate := &nativeModelCompletionGate{mockInspector: inspector, entered: make(chan struct{}), release: make(chan struct{})}
	adapter.proxy.inspector = gate
	nativeModelSetTransport(t, adapter, nativeModelRoundTrip(func(*http.Request) (*http.Response, error) {
		return nativeModelOK(), nil
	}))
	sink := &nativeModelCommitWriter{header: make(http.Header)}
	outcome := make(chan any, 1)
	go func() {
		defer func() { outcome <- recover() }()
		adapter.ServeHTTP(sink, nativeModelRequest(nativeModelTestBody))
	}()
	var release sync.Once
	defer release.Do(func() { close(gate.release) })
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("completion inspection did not enter")
	}
	wait, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if err := adapter.SealAndQuiesce(wait); err != nil {
		t.Fatalf("quiescence waited for whole request: %v", err)
	}
	release.Do(func() { close(gate.release) })
	select {
	case got := <-outcome:
		if got != http.ErrAbortHandler {
			t.Fatalf("sealed inspection ended with unexpected result: %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sealed inspection did not finish")
	}
	if sink.status != 0 || sink.body.Len() != 0 || sink.flushes != 0 {
		t.Fatal("sealed completion committed output")
	}
}
