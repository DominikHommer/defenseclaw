// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// A change event stays queued until every remote destination has it. The
// runtime tells the occurrence's RemoteDelivery the outcome of each
// destination; a replay of the stored record (WithStoredReplay) writes
// nothing locally and goes only to the destinations that did not
// acknowledge an earlier offer. After a restart (a new RemoteDelivery) the
// replay goes to every destination again. Before, an offer of a stored
// change exported nothing, so a delivery lost in memory was never redone.
func TestRuntimeReplaysAStoredChangeOnlyToDestinationsThatLackIt(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("acks", "none", 8),
				runtimeConsoleDestination("refuses", "none", 8),
			}
		},
	)
	adapters := map[string]*runtimeRecordingAdapter{
		"acks": newRuntimeRecordingAdapter(16), "refuses": newRuntimeRecordingAdapter(16),
	}
	adapters["refuses"].outcome = delivery.OutcomePermanentPayload
	factory := runtimeAdapterFactoryFunc(func(
		_ context.Context, destination config.ObservabilityV8EffectiveDestination, _ telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return adapters[destination.Name], func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)
	const recordID = "runtime-change-replay"
	offer := func(tracker *observability.RemoteDelivery, replay bool) {
		t.Helper()
		ctx := observability.WithExportAfterLocalWrite(t.Context(), runtimeRowDurable)
		if replay {
			ctx = observability.WithStoredReplay(t.Context(), storedRuntimeRecord(t, dependencies, recordID), runtimeRowDurable)
		}
		tracker.BeginAttempt()
		_, err := runtime.Emit(observability.WithRemoteDelivery(ctx, tracker), diagnosticMetadata(t),
			runtimeContentRecordBuilder(recordID, "change"))
		tracker.EndAttempt()
		if err != nil {
			t.Fatalf("offer (replay %t): %v", replay, err)
		}
	}
	settle := func(tracker *observability.RemoteDelivery) bool {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if settled, delivered := tracker.Settled(); settled {
				return delivered
			}
			if time.Now().After(deadline) {
				t.Fatal("the deliveries of the offer did not settle")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	received := func(name string) {
		t.Helper()
		if item := receiveRuntimeDelivery(t, adapters[name]); item.identity.RecordID != recordID {
			t.Fatalf("%s received %q", name, item.identity.RecordID)
		}
	}

	tracker := observability.NewRemoteDelivery()
	offer(tracker, false)
	received("acks")
	received("refuses")
	if settle(tracker) {
		t.Fatal("an offer a destination refused settled as delivered")
	}
	if !tracker.Acknowledged("acks") || tracker.Acknowledged("refuses") {
		t.Fatal("the acknowledgements are not per destination")
	}
	offer(tracker, true)
	received("refuses")
	assertNoRuntimeDelivery(t, adapters["acks"])
	if settle(tracker) {
		t.Fatal("a replay the destination refused again settled as delivered")
	}
	if n := countRuntimeRecord(t, dependencies, recordID); n != 1 {
		t.Fatalf("the replays left %d stored rows, want 1", n)
	}

	restarted := observability.NewRemoteDelivery()
	offer(restarted, true)
	received("acks")
	received("refuses")
	settle(restarted)
	if n := countRuntimeRecord(t, dependencies, recordID); n != 1 {
		t.Fatalf("the replay after a restart left %d stored rows, want 1", n)
	}

	// A replay writes nothing, so it cannot be one item of an atomic batch,
	// which writes every item.
	if _, err := runtime.EmitAtomicBatch(t.Context(), []LogBatchItem{{
		Context: observability.WithStoredReplay(t.Context(), storedRuntimeRecord(t, dependencies, recordID), runtimeRowDurable), Metadata: diagnosticMetadata(t),
		Builder: runtimeContentRecordBuilder("runtime-change-batch-replay", "change"),
	}}); err == nil {
		t.Fatal("an atomic batch took a stored replay")
	}
	assertNoRuntimeDelivery(t, adapters["acks"])
}

// storedRuntimeRecord is the projected record of the local row recordID.
func storedRuntimeRecord(t *testing.T, dependencies runtimeTestDependencies, recordID string) []byte {
	t.Helper()
	reader, err := sql.Open("sqlite", dependencies.storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close() //nolint:errcheck
	var record string
	if err := reader.QueryRowContext(t.Context(),
		`SELECT projected_record_json FROM audit_events WHERE id = ?`, recordID).Scan(&record); err != nil {
		t.Fatal(err)
	}
	return []byte(record)
}

// A stored change keeps the config generation and digest of the process
// that stored it. Before, a replay had to name the generation of the
// current graph, so once a reload (or a restart) replaced it, every replay
// of a change a destination had refused failed and the change stayed
// queued, filling the change spool. Now a replay keeps the stored
// provenance and is sent only when it is the stored record; another record
// under the stored id (this generation, another body) is refused, and a
// new record must still name this generation.
func TestRuntimeReplaysAStoredChangeAfterAReload(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	makePlan := func(generation string) *config.ObservabilityV8Plan {
		return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
			func(source *config.ObservabilityV8Source) {
				source.Resource.Attributes = map[string]string{"team.generation": generation}
				source.Destinations = []config.ObservabilityV8DestinationSource{
					runtimeConsoleDestination("refuses", "none", 8),
				}
			},
		)
	}
	adapter := newRuntimeRecordingAdapter(16)
	adapter.outcome = delivery.OutcomePermanentPayload
	factory := runtimeAdapterFactoryFunc(func(
		context.Context, config.ObservabilityV8EffectiveDestination, telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return adapter, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, makePlan("one"), factory, nil)
	const recordID = "runtime-change-reload"
	var first EmitContext
	storing := func(snapshot EmitContext, admission router.Admission) (observability.Record, error) {
		first = snapshot
		return runtimeContentRecordBuilder(recordID, "change")(snapshot, admission)
	}
	if _, err := runtime.Emit(observability.WithExportAfterLocalWrite(t.Context(), runtimeRowDurable), diagnosticMetadata(t), storing); err != nil {
		t.Fatal(err)
	}
	_ = receiveRuntimeDelivery(t, adapter)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	result, graphErr := runtime.Reload(ctx, runtimegraph.ConfigFromPlan(makePlan("two"), false))
	if graphErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload status=%v err=%v", result.Status(), graphErr)
	}
	if active := runtime.Active(); active.Generation() == first.Generation() || active.Digest() == first.Digest() {
		t.Fatal("the reload kept the generation and digest")
	}
	stored := storedRuntimeRecord(t, dependencies, recordID)
	replay := func(builder EmitBuilder) error {
		t.Helper()
		_, err := runtime.Emit(observability.WithStoredReplay(t.Context(), stored, runtimeRowDurable), diagnosticMetadata(t), builder)
		return err
	}
	asStored := func(content string) EmitBuilder {
		return func(_ EmitContext, admission router.Admission) (observability.Record, error) {
			return runtimeContentRecordBuilder(recordID, content)(first, admission)
		}
	}

	if err := replay(asStored("change")); err != nil {
		t.Fatalf("a replay of the stored change after a reload: %v", err)
	}
	item := receiveRuntimeDelivery(t, adapter)
	if item.identity.RecordID != recordID || !strings.Contains(string(item.bytes), first.Digest()) {
		t.Fatalf("the replay is not the stored record: %s", item.bytes)
	}
	for name, builder := range map[string]EmitBuilder{
		"this generation": runtimeContentRecordBuilder(recordID, "change"),
		"another body":    asStored("another change"),
	} {
		if err := replay(builder); err == nil {
			t.Fatalf("a replay with %s was accepted", name)
		}
		assertNoRuntimeDelivery(t, adapter)
	}
	stale := func(_ EmitContext, admission router.Admission) (observability.Record, error) {
		return runtimeContentRecordBuilder("runtime-change-stale", "stale")(first, admission)
	}
	if _, err := runtime.Emit(t.Context(), diagnosticMetadata(t), stale); err == nil {
		t.Fatal("a new record of the replaced generation was accepted")
	}
	assertNoRuntimeDelivery(t, adapter)
}
