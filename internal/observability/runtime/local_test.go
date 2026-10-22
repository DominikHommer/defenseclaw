// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func TestRuntimeRequiresAdapterForEnabledOptionalDestinationAndAllocatesNoneWhenDisabled(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	enabledPlan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{{
				Name: "future-console", Kind: config.ObservabilityV8DestinationConsole,
			}}
		},
	)
	_, err := New(t.Context(), runtimegraph.ConfigFromPlan(enabledPlan, false), dependencies.options())
	var graphErr *runtimegraph.Error
	if !errors.As(err, &graphErr) || graphErr.Code() != runtimegraph.ErrorInitialization ||
		graphErr.ComponentName() != DestinationDispatchComponentName {
		t.Fatalf("enabled optional destination error=%v", err)
	}

	disabled := false
	disabledPlan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{{
				Name: "future-console", Kind: config.ObservabilityV8DestinationConsole,
				Enabled: &disabled,
			}}
		},
	)
	runtime := newRuntimeForTest(t, dependencies, disabledPlan, false)
	destination, ok := runtime.Active().Plan().Destination("future-console")
	if !ok || destination.Enabled {
		t.Fatalf("disabled destination was not preserved: %#v", destination)
	}
}

// GAP-1100: a failed mandatory SQLite append counts as dropped on the
// local-sqlite destination and stays pending for the sqlite.write_failed
// report, while the optional destination still receives the record.
func TestRuntimeLocalWriteFailureIsCountedOnLocalSQLite(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("sink", "none", 8),
			}
		},
	)
	sink := newRuntimeRecordingAdapter(8)
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
	if _, err := runtime.Emit(t.Context(), diagnosticMetadata(t),
		runtimeContentRecordBuilder("runtime-local-full", "exported only")); err == nil {
		t.Fatal("the local append succeeded under a failing SQLite writer")
	}
	if item := receiveRuntimeDelivery(t, sink); item.identity.RecordID != "runtime-local-full" {
		t.Fatalf("sink received %q", item.identity.RecordID)
	}
	if _, err := database.Exec(`DROP TRIGGER local_history_full`); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Emit(t.Context(), diagnosticMetadata(t),
		runtimeContentRecordBuilder("runtime-local-stored", "stored")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := runtime.DestinationHealthSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	counters := destinationHealthByName(t, snapshot, config.ObservabilityV8LocalDestinationName).Counters
	if counters.Accepted != 2 || counters.Delivered != 1 || counters.Dropped != 1 {
		t.Fatalf("local-sqlite counters = %+v, want accepted 2 delivered 1 dropped 1", counters)
	}
	if lost := runtime.PendingLocalWriteLosses().Records; lost != 1 {
		t.Fatalf("pending local write losses = %d, want 1", lost)
	}
}

// Durable spool occurrences must not fan out on each failed SQLite retry.
func TestReplayableControlPlaneEventsExportOnlyAfterLocalPersistence(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{runtimeConsoleDestination("sink", "none", 8)}
		})
	sink := newRuntimeRecordingAdapter(8)
	factory := runtimeAdapterFactoryFunc(func(context.Context, config.ObservabilityV8EffectiveDestination, telemetry.V8ResourceContext) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return sink, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)
	db, err := sql.Open("sqlite", dependencies.storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER receipt_full BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
		t.Fatal(err)
	}
	action := observability.ProducerKey("config.bundle.receipt")
	classification := observability.ClassificationContext{RawSeverity: "INFO", EventName: observability.EventName(observability.TelemetryEventConfigBundleReceipt), Bucket: observability.BucketComplianceActivity, MandatoryFacts: observability.MandatoryFacts{ControlPlaneMutation: true}}
	meta, err := router.NewClassifiedLogMetadata(observability.ProducerAuditAction, action, classification, observability.SourceSystem, "", action)
	if err != nil {
		t.Fatal(err)
	}
	build := func(snapshot EmitContext, _ router.Admission) (observability.Record, error) {
		builder, err := observability.NewFamilyBuilder(observability.ClockFunc(func() time.Time { return time.Now().UTC() }), observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "receipt-retry", nil }))
		if err != nil {
			return observability.Record{}, err
		}
		severity := observability.NormalizeSeverity("INFO")
		return builder.BuildLogConfigBundleReceipt(observability.LogConfigBundleReceiptInput{
			Envelope: observability.FamilyEnvelopeInput{Source: observability.SourceSystem, Action: string(action), Phase: "apply",
				Provenance: observability.FamilyProvenanceInput{Producer: "runtime_test", BinaryVersion: "test", ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest()}},
			Severity: observability.Present(severity.Severity), LogLevel: observability.Present(severity.LogLevel),
			Outcome: observability.OutcomeApplied, DefenseClawAdminOperation: string(action),
			DefenseClawPolicyBundleReceiptID: "r-01JAZ3Y8Q2K7V4N6M5P0R9S8T7", DefenseClawPolicyBundleState: "confirmed", MandatoryControlPlaneMutation: true,
		})
	}
	for range 2 {
		if _, err := runtime.Emit(t.Context(), meta, build); err == nil {
			t.Fatal("SQLite failure was ignored")
		}
	}
	health, err := runtime.DestinationHealthSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := destinationHealthByName(t, health, "sink").Counters.Accepted; got != 0 {
		t.Fatalf("failed receipt queued %d remote exports", got)
	}
	if _, err := db.Exec(`DROP TRIGGER receipt_full`); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Emit(t.Context(), meta, build); err != nil {
		t.Fatal(err)
	}
	if item := receiveRuntimeDelivery(t, sink); item.identity.RecordID != "receipt-retry" {
		t.Fatalf("unexpected exported id %q", item.identity.RecordID)
	}
}
