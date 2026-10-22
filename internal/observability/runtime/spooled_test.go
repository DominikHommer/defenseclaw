// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func spooledTestPlan(t *testing.T, dependencies runtimeTestDependencies, retention int, logs bool, destinations ...string) *config.ObservabilityV8Plan {
	t.Helper()
	return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, retention, func(source *config.ObservabilityV8Source) {
		if !logs {
			disabled := false
			source.Defaults.Collect.Logs = &disabled
		}
		for _, name := range destinations {
			source.Destinations = append(source.Destinations, runtimeConsoleDestination(name, "none", 0))
		}
	})
}

func countSpooledRows(t *testing.T, dependencies runtimeTestDependencies, id string) int {
	t.Helper()
	rows, err := dependencies.store.ListEvents(64)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range rows {
		if row.ID == id {
			count++
		}
	}
	return count
}

// One destination that holds or refuses its acknowledgement must not hold
// the record back from another: the confirm phase admits the record to every
// destination before it waits on any, and succeeds only once all of them
// acknowledged it (W6 review, loop round 1).
func TestSpooledConfirmationAdmitsEveryDestinationBeforeWaiting(t *testing.T) {
	for _, outcome := range []delivery.DeliveryOutcome{delivery.OutcomeDelivered, delivery.OutcomeAuthentication} {
		t.Run(string(outcome), func(t *testing.T) {
			dependencies := newRuntimeTestDependencies(t)
			plan := spooledTestPlan(t, dependencies, 91, true, "stalled", "healthy")
			release := make(chan struct{})
			stalled, healthy := newRuntimeRecordingAdapter(16), newRuntimeRecordingAdapter(16)
			stalled.release, stalled.outcome = release, outcome
			factory := runtimeAdapterFactoryFunc(func(_ context.Context, destination config.ObservabilityV8EffectiveDestination, _ telemetry.V8ResourceContext) (delivery.Adapter, DestinationAdapterCleanup, error) {
				if destination.Name == "stalled" {
					return stalled, func(context.Context) error { return nil }, nil
				}
				return healthy, func(context.Context) error { return nil }, nil
			})
			runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			const id = "spooled-two-destinations"
			var owed []string
			if _, err := runtime.EmitSpooled(ctx, activityMetadata(t), runtimeRecordBuilder(id, activityIdentity(), nil),
				SpooledEmission{Intent: func(destinations []string) error { owed = destinations; return nil }}); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(owed, []string{"stalled", "healthy"}) {
				t.Fatalf("recorded obligations = %v", owed)
			}
			select {
			case item := <-healthy.delivered:
				t.Fatalf("the persist phase delivered %s before confirmation", item.identity.RecordID)
			default:
			}
			done := make(chan error, 1)
			go func() {
				_, err := runtime.EmitSpooled(ctx, activityMetadata(t), runtimeRecordBuilder(id, activityIdentity(), nil),
					SpooledEmission{Confirm: true, Obligations: owed, Known: true})
				done <- err
			}()
			if item := receiveRuntimeDelivery(t, healthy); item.identity.RecordID != id {
				t.Fatalf("healthy destination received %s", item.identity.RecordID)
			}
			<-stalled.started
			select {
			case err := <-done:
				t.Fatalf("confirmed before the stalled destination answered: %v", err)
			default:
			}
			close(release)
			if err := <-done; (err == nil) != (outcome == delivery.OutcomeDelivered) {
				t.Fatalf("stalled destination outcome %s confirmed=%v", outcome, err)
			}
			if count := countSpooledRows(t, dependencies, id); count != 1 {
				t.Fatalf("local rows = %d, want 1", count)
			}
		})
	}
}

// A committed row whose marker was lost is confirmed after a restart under
// whatever routing is current. Logs turned off must not keep a row that owed
// no destination pending forever, and a route change must not drop a
// destination the row owed when it committed (W6 review, loop round 1).
func TestSpooledConfirmationFollowsRecordedObligationsAcrossRouteChanges(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	adapter := newRuntimeRecordingAdapter(16)
	factory := runtimeAdapterFactoryFunc(func(context.Context, config.ObservabilityV8EffectiveDestination, telemetry.V8ResourceContext) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return adapter, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, spooledTestPlan(t, dependencies, 91, true, "receipt-destination"), factory, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	reload := func(plan *config.ObservabilityV8Plan) {
		t.Helper()
		if _, err := runtime.Reload(ctx, runtimegraph.ConfigFromPlan(plan, false)); err != nil {
			t.Fatal(err)
		}
	}
	persist := func(id string) []string {
		t.Helper()
		var owed []string
		outcome, err := runtime.EmitSpooled(ctx, activityMetadata(t), runtimeRecordBuilder(id, activityIdentity(), nil),
			SpooledEmission{Intent: func(destinations []string) error { owed = destinations; return nil }})
		if err != nil || !outcome.LocalPersisted() {
			t.Fatalf("persist %s: persisted=%t %v", id, outcome.LocalPersisted(), err)
		}
		return owed
	}
	confirm := func(id string, owed []string, known bool) error {
		_, err := runtime.EmitSpooled(ctx, activityMetadata(t), runtimeRecordBuilder(id, activityIdentity(), nil),
			SpooledEmission{Confirm: true, Obligations: owed, Known: known})
		return err
	}
	const owing, local = "spooled-owes-destination", "spooled-local-only"
	owed := persist(owing)
	if !slices.Equal(owed, []string{"receipt-destination"}) {
		t.Fatalf("obligations = %v", owed)
	}
	reload(spooledTestPlan(t, dependencies, 92, true))
	if none := persist(local); len(none) != 0 {
		t.Fatalf("a row without destinations owes %v", none)
	}

	// Ordinary log collection turned off: floor-only routing.
	reload(spooledTestPlan(t, dependencies, 93, false, "receipt-destination"))
	if err := confirm(local, nil, true); err != nil {
		t.Fatalf("a row with no remote obligation stayed pending after logs were turned off: %v", err)
	}
	if err := confirm(local, nil, false); err != nil {
		t.Fatalf("an unrecorded row under floor-only routing stayed pending: %v", err)
	}
	var pipelineErr *pipeline.Error
	if err := confirm(owing, owed, true); !errors.As(err, &pipelineErr) || pipelineErr.Code() != pipeline.ErrorDeliveryObligation {
		t.Fatalf("logs turned off dropped an earlier remote obligation: %v", err)
	}
	// The destination is removed: the obligation still holds.
	reload(spooledTestPlan(t, dependencies, 94, true))
	if err := confirm(owing, owed, true); err == nil {
		t.Fatal("removing the destination dropped an earlier remote obligation")
	}
	select {
	case item := <-adapter.delivered:
		t.Fatalf("delivered %s while its obligation was unroutable", item.identity.RecordID)
	default:
	}
	// The destination is back: the owed delivery completes.
	reload(spooledTestPlan(t, dependencies, 95, true, "receipt-destination"))
	if err := confirm(owing, owed, true); err != nil {
		t.Fatal(err)
	}
	if item := receiveRuntimeDelivery(t, adapter); item.identity.RecordID != owing {
		t.Fatalf("delivered %s, want %s", item.identity.RecordID, owing)
	}
	for _, id := range []string{owing, local} {
		if count := countSpooledRows(t, dependencies, id); count != 1 {
			t.Fatalf("%s local rows = %d, want 1", id, count)
		}
	}
}

// A failed intent record keeps the row out of SQLite, so the next attempt
// starts clean instead of committing a row with an unknown obligation.
func TestSpooledPersistWritesNoRowWithoutItsObligationRecord(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	runtime := newRuntimeForTest(t, dependencies, spooledTestPlan(t, dependencies, 91, true), false)
	const id = "spooled-intent-failed"
	_, err := runtime.EmitSpooled(t.Context(), activityMetadata(t), runtimeRecordBuilder(id, activityIdentity(), nil),
		SpooledEmission{Intent: func([]string) error { return errors.New("disk full") }})
	var pipelineErr *pipeline.Error
	if !errors.As(err, &pipelineErr) || pipelineErr.Code() != pipeline.ErrorDeliveryIntent {
		t.Fatalf("persist with a failed intent = %v", err)
	}
	if count := countSpooledRows(t, dependencies, id); count != 0 {
		t.Fatalf("local rows = %d, want none", count)
	}
}
