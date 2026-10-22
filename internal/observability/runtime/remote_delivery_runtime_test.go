// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
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
		ctx := observability.WithExportAfterLocalWrite(t.Context())
		if replay {
			ctx = observability.WithStoredReplay(t.Context())
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
		Context: observability.WithStoredReplay(t.Context()), Metadata: diagnosticMetadata(t),
		Builder: runtimeContentRecordBuilder("runtime-change-batch-replay", "change"),
	}}); err == nil {
		t.Fatal("an atomic batch took a stored replay")
	}
	assertNoRuntimeDelivery(t, adapters["acks"])
}
