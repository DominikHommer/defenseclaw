// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// pollSettled runs one poll and waits for the deliveries it started; run
// records their markers the same way as each one finishes.
func pollSettled(r *bundleReceiptReporter) {
	r.poll(context.Background())
	r.settle()
}

func (r *bundleReceiptReporter) settle() {
	r.confirmations.Wait()
	r.drainResults()
}

func writeTestReceiptBacklog(t *testing.T, receiptPath string, count int) []string {
	t.Helper()
	spool := filepath.Join(filepath.Dir(receiptPath), enterprisestatus.PublicReceiptEventsDirName)
	ids := make([]string, 0, count)
	for i := range count {
		id := fmt.Sprintf("b-01JAZ3Y8Q2K7V4N6M5P0R9%04d", i)
		writeTestPublicReceipt(t, filepath.Join(spool, id+".json"), enterprisestatus.PublicReceipt{SchemaVersion: 1,
			ReceiptID: id, BundleID: id, Version: 3, State: enterprisestatus.BundleConfirmed,
			FinishedAt: fmt.Sprintf("2026-10-12T10:%02d:%02d.000Z", i/60, i%60)})
		ids = append(ids, id)
	}
	return ids
}

// A destination that never acknowledges holds neither the poll nor the local
// audit rows of later receipts and changes. Each poll writes a bounded number
// of rows, changes take turns with the receipt backlog, and nothing is marked
// reported before its delivery is acknowledged (W6 review, loop round 1).
func TestBundleReceiptReporterPersistsChangesWhileDeliveriesStall(t *testing.T) {
	dir := t.TempDir()
	receipts := enterprisestatus.PublicReceiptPath(dir)
	gate := make(chan struct{})
	sink := &fakeBundleReceiptSink{confirmGate: gate}
	r := &bundleReceiptReporter{receiptPath: receipts, markerPath: filepath.Join(dir, bundleReceiptMarkerName),
		sink: sink, enforcedVersion: func() uint64 { return 0 }}
	const backlog = 40
	ids := writeTestReceiptBacklog(t, receipts, backlog)
	change := writeTestChangeEvent(t, enterprisestatus.ChangeEventsDir(dir), enterprisestatus.ChangeKindSecret,
		enterprisestatus.ChangeActionSet, enterprisestatus.ChangeApplied, "", func(ev *enterprisestatus.ChangeEvent) { ev.SecretName = "otlp-token" })
	t.Cleanup(func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
		r.settle()
	})

	started := time.Now()
	r.poll(context.Background())
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("one poll waited %s on unacknowledged deliveries", elapsed)
	}
	persistedReceipts, changes := sink.persistedCounts()
	if changes != 1 {
		t.Fatal("the change's local audit row waited behind the receipt backlog")
	}
	if persistedReceipts != bundleReportPersistPerPoll-1 {
		t.Fatalf("one poll wrote %d receipt rows, want %d", persistedReceipts, bundleReportPersistPerPoll-1)
	}
	if len(r.inFlight) != bundleReportConfirmInFlight {
		t.Fatalf("deliveries in flight = %d, want %d", len(r.inFlight), bundleReportConfirmInFlight)
	}
	r.poll(context.Background())
	if persistedReceipts, _ = sink.persistedCounts(); persistedReceipts != backlog {
		t.Fatalf("receipt rows after two polls = %d, want the whole backlog of %d", persistedReceipts, backlog)
	}
	if r.hasSeen(change.EventID) || enterprisestatus.ChangeReported(dir, change.EventID) || r.hasSeen(ids[0]) {
		t.Fatal("an unacknowledged delivery was marked reported")
	}

	close(gate)
	for range 2 * (backlog + 1) {
		pollSettled(r)
	}
	for _, id := range append(ids, change.EventID) {
		if !r.hasSeen(id) {
			t.Fatalf("%s was never marked reported after its delivery was acknowledged", id)
		}
	}
	if persistedReceipts, changes = sink.persistedCounts(); persistedReceipts != backlog || changes != 1 {
		t.Fatalf("local rows written: receipts=%d changes=%d, want each once", persistedReceipts, changes)
	}
}

// A receipt whose delivery keeps failing goes to the back of the queue: the
// others are delivered and marked while it stays pending.
func TestBundleReceiptReporterDoesNotLetOneFailingDeliveryStarveTheOthers(t *testing.T) {
	dir := t.TempDir()
	receipts := enterprisestatus.PublicReceiptPath(dir)
	ids := writeTestReceiptBacklog(t, receipts, 3*bundleReportConfirmInFlight)
	sink := &fakeBundleReceiptSink{confirmFail: map[string]bool{ids[0]: true}}
	r := &bundleReceiptReporter{receiptPath: receipts, markerPath: filepath.Join(dir, bundleReceiptMarkerName),
		sink: sink, enforcedVersion: func() uint64 { return 0 }}
	for range 4 {
		pollSettled(r)
	}
	if r.hasSeen(ids[0]) {
		t.Fatal("a refused delivery was marked reported")
	}
	for _, id := range ids[1:] {
		if !r.hasSeen(id) {
			t.Fatalf("%s waited behind a delivery that keeps failing", id)
		}
	}
	if persistedReceipts, _ := sink.persistedCounts(); persistedReceipts != len(ids) {
		t.Fatalf("receipt rows = %d, want each once (%d): a failed delivery repeated its local row", persistedReceipts, len(ids))
	}
}
