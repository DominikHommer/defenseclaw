// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"database/sql"
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
	marked := observability.WithExportAfterLocalWrite(t.Context())
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
