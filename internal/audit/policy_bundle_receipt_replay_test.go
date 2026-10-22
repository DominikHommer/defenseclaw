// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

type receiptReplayEmitter struct {
	*testRuntimeV8Emitter
	refuse   bool
	attempts int
}

func (e *receiptReplayEmitter) EmitRuntimeV8(ctx context.Context, m router.Metadata, b RuntimeV8Builder) (RuntimeV8EmitOutcome, error) {
	out, err := e.testRuntimeV8Emitter.EmitRuntimeV8(ctx, m, b)
	if err != nil {
		return out, err
	}
	e.attempts++
	if e.refuse {
		return out, fmt.Errorf("destination acknowledgement unavailable")
	}
	return out, nil
}

func (e *receiptReplayEmitter) EmitRuntimeV8Confirmed(ctx context.Context, m router.Metadata, b RuntimeV8Builder, replay bool) (RuntimeV8EmitOutcome, error) {
	if !replay {
		return e.EmitRuntimeV8(ctx, m, b)
	}
	e.attempts++
	if e.refuse {
		return RuntimeV8EmitOutcome{}, fmt.Errorf("destination acknowledgement unavailable")
	}
	return e.testRuntimeV8Emitter.EmitRuntimeV8Confirmed(ctx, m, b, true)
}

func TestPolicyBundleReceiptReplayKeepsOneLocalRowUntilDeliveryIsConfirmed(t *testing.T) {
	l := newTestLogger(t)
	e := &receiptReplayEmitter{testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, l.store, router.AdmissionOrdinary), refuse: true}
	l.SetRuntimeV8Emitter(e)
	bundle := PolicyBundle{ID: testPolicyBundleID, Version: 5}
	receipt := PolicyBundleReceipt{ReceiptID: testPolicyBundleID, State: PolicyBundleConfirmed, FinishedAt: "2020-01-01T00:00:00Z"}
	started := time.Now().UTC()
	if err := l.LogPolicyBundleReceipt("operator:sample", bundle, receipt); err == nil {
		t.Fatal("unacknowledged delivery succeeded")
	}
	assertOneApplyMetric := func() {
		t.Helper()
		count := 0
		for _, metric := range e.metricSnapshot() {
			if metric.EventName() == observability.EventName(observability.TelemetryInstrumentDefenseClawPolicyBundleApplies) {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("receipt apply metrics=%d, want one independently of destination acknowledgement", count)
		}
	}
	assertOneApplyMetric()
	e.refuse = false
	// A reader pinned before a later WAL write prevents a complete durability
	// checkpoint. Remote acknowledgement alone must not retire the receipt.
	db, err := l.store.checkpointConn()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	var count int
	if err := reader.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM audit_events").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if _, err := l.store.db.Exec("CREATE TABLE receipt_checkpoint_test (value INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if err := l.LogPolicyBundleReceipt("operator:sample", bundle, receipt); err == nil {
		t.Fatal("incomplete local durability checkpoint succeeded")
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := l.LogPolicyBundleReceipt("operator:sample", bundle, receipt); err != nil {
		t.Fatal(err)
	}
	rows, err := l.store.ListEvents(10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("replayed receipt rows=%d, want one: %v", len(rows), err)
	}
	if rows[0].Timestamp.Before(started) {
		t.Fatal("reporting an older receipt backdated its new audit row and metric retention window")
	}
	if e.attempts != 3 {
		t.Fatalf("delivery attempts=%d, want 3", e.attempts)
	}
	assertOneApplyMetric()
}
