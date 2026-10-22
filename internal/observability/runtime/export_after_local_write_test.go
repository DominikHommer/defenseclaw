// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// A trust anchor or credential change event is offered again until the
// local store records it. While SQLite reads but cannot insert, an
// occurrence marked WithExportAfterLocalWrite reaches no optional
// destination, through Emit or an atomic batch, however often it is
// offered; once the write succeeds it is exported. An unmarked record is
// still exported while the store is down (GAP-1536). Before, every failed
// offer of the change exported it again.
func TestRuntimeExportsMarkedRecordsOnlyAfterTheLocalWrite(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("sink", "none", 8),
			}
		},
	)
	sink := newRuntimeRecordingAdapter(16)
	factory := runtimeAdapterFactoryFunc(func(
		context.Context, config.ObservabilityV8EffectiveDestination, telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return sink, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)
	database, err := sql.Open("sqlite", dependencies.storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`CREATE TRIGGER local_history_full BEFORE INSERT ON audit_events
		BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
		t.Fatal(err)
	}
	marked := observability.WithExportAfterLocalWrite(t.Context(), runtimeRowDurable)
	offer := func() (emitErr, batchErr error) {
		_, emitErr = runtime.Emit(marked, diagnosticMetadata(t),
			runtimeContentRecordBuilder("runtime-change-single", "change"))
		_, batchErr = runtime.EmitAtomicBatch(t.Context(), []LogBatchItem{{
			Context: marked, Metadata: diagnosticMetadata(t),
			Builder: runtimeContentRecordBuilder("runtime-change-batch", "change"),
		}})
		return emitErr, batchErr
	}
	for attempt := 0; attempt < 3; attempt++ {
		if emitErr, batchErr := offer(); emitErr == nil || batchErr == nil {
			t.Fatalf("offer %d stored under a failing SQLite writer: %v / %v", attempt, emitErr, batchErr)
		}
	}
	assertNoRuntimeDelivery(t, sink)
	if _, err := runtime.Emit(t.Context(), diagnosticMetadata(t),
		runtimeContentRecordBuilder("runtime-unmarked", "exported while the store is down")); err == nil {
		t.Fatal("the unmarked append succeeded under a failing SQLite writer")
	}
	if item := receiveRuntimeDelivery(t, sink); item.identity.RecordID != "runtime-unmarked" {
		t.Fatalf("sink received %q, want the unmarked record", item.identity.RecordID)
	}
	if _, err := database.Exec(`DROP TRIGGER local_history_full`); err != nil {
		t.Fatal(err)
	}
	if emitErr, batchErr := offer(); emitErr != nil || batchErr != nil {
		t.Fatalf("offer after the store recovered: %v / %v", emitErr, batchErr)
	}
	got := map[string]int{}
	for range 2 {
		got[receiveRuntimeDelivery(t, sink).identity.RecordID]++
	}
	if got["runtime-change-single"] != 1 || got["runtime-change-batch"] != 1 {
		t.Fatalf("deliveries after the store recovered = %v", got)
	}
	assertNoRuntimeDelivery(t, sink)
}

// runtimeRowDurable is the durability step of a test change whose store
// needs no flush.
func runtimeRowDurable(context.Context) error { return nil }

// requireRuntimeErrorCode fails unless err is a runtime *Error with code.
func requireRuntimeErrorCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	var runtimeErr *Error
	if !errors.As(err, &runtimeErr) || runtimeErr.Code() != code {
		t.Fatalf("error = %v, want runtime code %s", err, code)
	}
}

// A change event reaches a remote destination only once its local row
// survives a power loss: the runtime runs the occurrence's durability step
// after the local write and before any destination gets the record, through
// Emit, an atomic batch and a stored replay. When the step fails no
// destination gets the record, the emit fails and the attempt is not
// delivered; a marked occurrence without a step is refused before anything
// is written. Before, the first offer was queued for its destinations
// before its row was flushed, so a sink could acknowledge a record a power
// loss then took back, and the next offer sent another record (another
// time, run and sidecar) under the same id.
func TestRuntimeExportsAChangeOnlyOnceItsRowIsDurable(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("sink", "none", 8),
			}
		},
	)
	sink := newRuntimeRecordingAdapter(16)
	factory := runtimeAdapterFactoryFunc(func(
		context.Context, config.ObservabilityV8EffectiveDestination, telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return sink, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)
	var ran []string
	step := func(recordID string, fail bool) func(context.Context) error {
		return func(context.Context) error {
			if n := countRuntimeRecord(t, dependencies, recordID); n != 1 {
				t.Errorf("the durability step of %s ran with %d stored rows, want 1", recordID, n)
			}
			if len(sink.delivered) != 0 {
				t.Errorf("a destination got a record before the durability step of %s", recordID)
			}
			ran = append(ran, recordID)
			if fail {
				return errors.New("disk I/O error")
			}
			return nil
		}
	}
	emit := func(recordID string, fail, replay bool) (*observability.RemoteDelivery, error) {
		t.Helper()
		ctx := observability.WithExportAfterLocalWrite(t.Context(), step(recordID, fail))
		if replay {
			ctx = observability.WithStoredReplay(t.Context(),
				storedRuntimeRecord(t, dependencies, recordID), step(recordID, fail))
		}
		tracker := observability.NewRemoteDelivery()
		tracker.BeginAttempt()
		defer tracker.EndAttempt()
		_, err := runtime.Emit(observability.WithRemoteDelivery(ctx, tracker), diagnosticMetadata(t),
			runtimeContentRecordBuilder(recordID, "change"))
		return tracker, err
	}
	batch := func(recordID string, fail bool) error {
		t.Helper()
		_, err := runtime.EmitAtomicBatch(t.Context(), []LogBatchItem{{
			Context:  observability.WithExportAfterLocalWrite(t.Context(), step(recordID, fail)),
			Metadata: diagnosticMetadata(t), Builder: runtimeContentRecordBuilder(recordID, "change"),
		}})
		return err
	}
	received := func(recordID string) {
		t.Helper()
		if item := receiveRuntimeDelivery(t, sink); item.identity.RecordID != recordID {
			t.Fatalf("sink received %q, want %q", item.identity.RecordID, recordID)
		}
		assertNoRuntimeDelivery(t, sink)
	}

	tracker, err := emit("runtime-durable-fails", true, false)
	requireRuntimeErrorCode(t, err, ErrorLocalNotDurable)
	assertNoRuntimeDelivery(t, sink)
	tracker.EndAttempt()
	if settled, delivered := tracker.Settled(); !settled || delivered {
		t.Fatalf("an offer whose row is not durable settled=%t delivered=%t", settled, delivered)
	}
	requireRuntimeErrorCode(t, batch("runtime-durable-batch-fails", true), ErrorLocalNotDurable)
	assertNoRuntimeDelivery(t, sink)
	// The stored row is replayed only once it is durable too.
	_, err = emit("runtime-durable-fails", true, true)
	requireRuntimeErrorCode(t, err, ErrorLocalNotDurable)
	assertNoRuntimeDelivery(t, sink)

	if _, err := emit("runtime-durable-single", false, false); err != nil {
		t.Fatal(err)
	}
	received("runtime-durable-single")
	if err := batch("runtime-durable-batch", false); err != nil {
		t.Fatal(err)
	}
	received("runtime-durable-batch")
	if _, err := emit("runtime-durable-fails", false, true); err != nil {
		t.Fatal(err)
	}
	received("runtime-durable-fails")
	want := []string{
		"runtime-durable-fails", "runtime-durable-batch-fails", "runtime-durable-fails",
		"runtime-durable-single", "runtime-durable-batch", "runtime-durable-fails",
	}
	if len(ran) != len(want) {
		t.Fatalf("durability steps ran for %v, want %v", ran, want)
	}
	for index := range want {
		if ran[index] != want[index] {
			t.Fatalf("durability steps ran for %v, want %v", ran, want)
		}
	}
	for _, recordID := range []string{"runtime-durable-fails", "runtime-durable-batch-fails"} {
		if n := countRuntimeRecord(t, dependencies, recordID); n != 1 {
			t.Fatalf("%s has %d stored rows, want 1", recordID, n)
		}
	}

	// A change marked without a durability step is refused before it is
	// written, alone or in a batch.
	if _, err := runtime.Emit(observability.WithExportAfterLocalWrite(t.Context(), nil),
		diagnosticMetadata(t), runtimeContentRecordBuilder("runtime-durable-none", "change")); err == nil {
		t.Fatal("a change without a durability step was accepted")
	} else {
		requireRuntimeErrorCode(t, err, ErrorInvalidDependency)
	}
	if _, err := runtime.EmitAtomicBatch(t.Context(), []LogBatchItem{{
		Context:  observability.WithExportAfterLocalWrite(t.Context(), nil),
		Metadata: diagnosticMetadata(t), Builder: runtimeContentRecordBuilder("runtime-durable-none", "change"),
	}}); err == nil {
		t.Fatal("a batched change without a durability step was accepted")
	}
	if n := countRuntimeRecord(t, dependencies, "runtime-durable-none"); n != 0 {
		t.Fatalf("a refused change left %d stored rows", n)
	}
	assertNoRuntimeDelivery(t, sink)
}
