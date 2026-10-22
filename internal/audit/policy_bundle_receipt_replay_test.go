// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

type receiptReplayEmitter struct {
	*testRuntimeV8Emitter
	refuse   bool
	attempts int
	spools   []RuntimeV8Spool
}

func (e *receiptReplayEmitter) EmitRuntimeV8Spooled(ctx context.Context, m router.Metadata, b RuntimeV8Builder, spool RuntimeV8Spool) (RuntimeV8EmitOutcome, error) {
	e.spools = append(e.spools, spool)
	if spool.Confirm {
		e.attempts++
		if e.refuse {
			return RuntimeV8EmitOutcome{}, fmt.Errorf("destination acknowledgement unavailable")
		}
	}
	return e.testRuntimeV8Emitter.EmitRuntimeV8Spooled(ctx, m, b, spool)
}

func TestPolicyBundleReceiptReplayKeepsOneLocalRowUntilDeliveryIsConfirmed(t *testing.T) {
	l := newTestLogger(t)
	e := &receiptReplayEmitter{testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, l.store, router.AdmissionOrdinary), refuse: true}
	l.SetRuntimeV8Emitter(e)
	bundle := PolicyBundle{ID: testPolicyBundleID, Version: 5}
	receipt := PolicyBundleReceipt{ReceiptID: testPolicyBundleID, State: PolicyBundleConfirmed, FinishedAt: "2020-01-01T00:00:00Z"}
	started := time.Now().UTC()
	if err := l.LogPolicyBundleReceipt("operator:sample", bundle, receipt); err != nil {
		t.Fatalf("local persistence depended on a destination: %v", err)
	}
	if err := l.ConfirmPolicyBundleReceipt(t.Context(), "operator:sample", bundle, receipt); err == nil {
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
	// A reader pinned before a later WAL write prevents a complete durability
	// checkpoint. The persist phase of a replay must report it.
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
	e.refuse = false
	if err := l.ConfirmPolicyBundleReceipt(t.Context(), "operator:sample", bundle, receipt); err != nil {
		t.Fatal(err)
	}
	rows, err := l.store.ListEvents(10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("replayed receipt rows=%d, want one: %v", len(rows), err)
	}
	if rows[0].Timestamp.Before(started) {
		t.Fatal("reporting an older receipt backdated its new audit row and metric retention window")
	}
	if e.attempts != 2 {
		t.Fatalf("delivery attempts=%d, want 2", e.attempts)
	}
	assertOneApplyMetric()
}

func TestConfigChangeReplayRequiresAcknowledgementAfterLocalPersistence(t *testing.T) {
	for _, change := range []ConfigChange{
		{EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "install", Outcome: ConfigChangeRefused, ReasonCode: "lifecycle_busy"},
		{EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set", Outcome: ConfigChangeApplied, SecretName: "test-credential"},
		{EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "remove", Outcome: ConfigChangeFailed, ReasonCode: "change_failed", SecretName: "test-credential"},
	} {
		t.Run(change.Kind+"/"+change.Outcome, func(t *testing.T) {
			l := newTestLogger(t)
			e := &receiptReplayEmitter{testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, l.store, router.AdmissionOrdinary), refuse: true}
			l.SetRuntimeV8Emitter(e)
			if err := l.LogConfigChange(change); err != nil {
				t.Fatal(err)
			}
			if err := l.ConfirmConfigChange(t.Context(), change); err == nil {
				t.Fatal("unacknowledged change succeeded")
			}
			e.refuse = false
			if err := l.LogConfigChange(change); err != nil {
				t.Fatal(err)
			}
			if err := l.ConfirmConfigChange(t.Context(), change); err != nil {
				t.Fatal(err)
			}
			if e.attempts != 2 {
				t.Fatalf("delivery attempts=%d, want a replay after the first local commit", e.attempts)
			}
			rows, err := l.store.ListEvents(10)
			if err != nil || len(rows) != 1 {
				t.Fatalf("replayed change rows=%d, want one: %v", len(rows), err)
			}
		})
	}
}

// The persist phase records the destinations a row owes before the row
// commits. A restarted logger confirms against that record, whatever the
// routing is then, and the record is removed once delivery is confirmed
// (W6 review, loop round 1).
func TestSpooledReceiptKeepsItsDeliveryObligationsAcrossARestart(t *testing.T) {
	l := newTestLogger(t)
	e := &receiptReplayEmitter{testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, l.store, router.AdmissionOrdinary)}
	e.spoolDestinations = []string{"siem", "archive"}
	l.SetRuntimeV8Emitter(e)
	bundle := PolicyBundle{ID: testPolicyBundleID, Version: 5}
	receipt := PolicyBundleReceipt{ReceiptID: testPolicyBundleID, State: PolicyBundleConfirmed, FinishedAt: "2026-10-22T10:00:00Z"}
	if err := l.ConfirmPolicyBundleReceipt(t.Context(), "operator:sample", bundle, receipt); err == nil {
		t.Fatal("a receipt without a local row was confirmed")
	}
	if err := l.LogPolicyBundleReceipt("operator:sample", bundle, receipt); err != nil {
		t.Fatal(err)
	}

	restarted := NewLogger(l.store)
	after := &receiptReplayEmitter{testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, l.store, router.AdmissionOrdinary)}
	restarted.SetRuntimeV8Emitter(after)
	if err := restarted.LogPolicyBundleReceipt("operator:sample", bundle, receipt); err != nil {
		t.Fatal(err)
	}
	if len(after.spools) != 0 {
		t.Fatalf("the persist phase of a stored row emitted again: %+v", after.spools)
	}
	if err := restarted.ConfirmPolicyBundleReceipt(t.Context(), "operator:sample", bundle, receipt); err != nil {
		t.Fatal(err)
	}
	if len(after.spools) != 1 || !after.spools[0].Confirm || !after.spools[0].Known ||
		!slices.Equal(after.spools[0].Obligations, []string{"archive", "siem"}) {
		t.Fatalf("confirm after a restart = %+v, want the recorded obligations", after.spools)
	}
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(l.store.dbPath), spoolObligationsDirName))
	if err != nil || len(entries) != 0 {
		t.Fatalf("obligation records after confirmation = %d, %v; want none", len(entries), err)
	}
	if rows, err := l.store.ListEvents(10); err != nil || len(rows) != 1 {
		t.Fatalf("receipt rows=%d, want one: %v", len(rows), err)
	}
}

// Any doubt about a row's obligations blocks its confirmation; a destination
// name that cannot be recorded keeps the row out of the store.
func TestSpooledReceiptObligationDoubtBlocks(t *testing.T) {
	l := newTestLogger(t)
	e := &receiptReplayEmitter{testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, l.store, router.AdmissionOrdinary)}
	e.spoolDestinations = []string{"not a token"}
	l.SetRuntimeV8Emitter(e)
	bundle := PolicyBundle{ID: testPolicyBundleID, Version: 5}
	receipt := PolicyBundleReceipt{ReceiptID: testPolicyBundleID, State: PolicyBundleConfirmed, FinishedAt: "2026-10-22T10:00:00Z"}
	if err := l.LogPolicyBundleReceipt("operator:sample", bundle, receipt); err == nil {
		t.Fatal("a row whose obligations could not be recorded was persisted")
	}
	if rows, err := l.store.ListEvents(10); err != nil || len(rows) != 0 {
		t.Fatalf("receipt rows=%d, want none: %v", len(rows), err)
	}
	e.spoolDestinations = []string{"siem"}
	if err := l.LogPolicyBundleReceipt("operator:sample", bundle, receipt); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(filepath.Dir(l.store.dbPath), spoolObligationsDirName)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("obligation records = %d, %v; want one", len(entries), err)
	}
	if err := os.WriteFile(filepath.Join(dir, entries[0].Name()), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.ConfirmPolicyBundleReceipt(t.Context(), "operator:sample", bundle, receipt); err == nil {
		t.Fatal("a row with an unreadable obligation record was confirmed")
	}
}

// ceilingSpoolDestinations is the largest valid routing of one spooled item:
// every operator destination the compiler accepts, each named with the
// longest stable token, plus the generated managed-enterprise destination.
func ceilingSpoolDestinations(t *testing.T) []string {
	t.Helper()
	names := make([]string, 0, config.ObservabilityV8MaxDestinations)
	for index := range config.ObservabilityV8MaxSourceDestinations {
		prefix := fmt.Sprintf("operator-%02d-", index)
		names = append(names, prefix+strings.Repeat("x", observability.MaxStableTokenBytes-len(prefix)))
	}
	names = append(names, config.ObservabilityV8ManagedAIDDestinationName)
	if len(names) != config.ObservabilityV8MaxDestinations {
		t.Fatalf("ceiling routing names %d destinations, want %d", len(names), config.ObservabilityV8MaxDestinations)
	}
	return names
}

// A spooled receipt or change audit that selects every destination the
// compiler accepts (64 operator destinations and the generated managed one)
// is persisted locally and confirmed against all of them after a restart. One
// more than the compiled ceiling is still a doubt that keeps the row out of
// the store (W6 review, loop round 2).
func TestSpooledObligationsCoverTheCompiledDestinationCeiling(t *testing.T) {
	bundle := PolicyBundle{ID: testPolicyBundleID, Version: 5}
	receipt := PolicyBundleReceipt{ReceiptID: testPolicyBundleID, State: PolicyBundleConfirmed, FinishedAt: "2026-10-22T10:00:00Z"}
	change := ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "install", Outcome: ConfigChangeApplied}
	for _, item := range []struct {
		name    string
		log     func(*Logger) error
		confirm func(*Logger) error
	}{
		{
			name: "policy-bundle-receipt",
			log:  func(l *Logger) error { return l.LogPolicyBundleReceipt("operator:sample", bundle, receipt) },
			confirm: func(l *Logger) error {
				return l.ConfirmPolicyBundleReceipt(t.Context(), "operator:sample", bundle, receipt)
			},
		},
		{
			name:    "config-change",
			log:     func(l *Logger) error { return l.LogConfigChange(change) },
			confirm: func(l *Logger) error { return l.ConfirmConfigChange(t.Context(), change) },
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			ceiling := ceilingSpoolDestinations(t)

			over := newTestLogger(t)
			refused := &receiptReplayEmitter{testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, over.store, router.AdmissionOrdinary)}
			refused.spoolDestinations = append(slices.Clone(ceiling), "one-past-the-ceiling")
			over.SetRuntimeV8Emitter(refused)
			if err := item.log(over); err == nil {
				t.Fatal("a routing past the compiled destination ceiling was recorded")
			}
			if rows, err := over.store.ListEvents(10); err != nil || len(rows) != 0 {
				t.Fatalf("rows past the ceiling = %d, %v; want none", len(rows), err)
			}

			l := newTestLogger(t)
			e := &receiptReplayEmitter{testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, l.store, router.AdmissionOrdinary)}
			e.spoolDestinations = ceiling
			l.SetRuntimeV8Emitter(e)
			if err := item.log(l); err != nil {
				t.Fatalf("the compiled destination ceiling kept the row out of the store: %v", err)
			}
			if rows, err := l.store.ListEvents(10); err != nil || len(rows) != 1 {
				t.Fatalf("rows at the ceiling = %d, %v; want one", len(rows), err)
			}

			restarted := NewLogger(l.store)
			after := &receiptReplayEmitter{testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, l.store, router.AdmissionOrdinary)}
			restarted.SetRuntimeV8Emitter(after)
			if err := item.confirm(restarted); err != nil {
				t.Fatalf("the recorded ceiling obligations were not readable: %v", err)
			}
			want := slices.Sorted(slices.Values(ceiling))
			if len(after.spools) != 1 || !after.spools[0].Confirm || !after.spools[0].Known ||
				!slices.Equal(after.spools[0].Obligations, want) {
				t.Fatalf("confirm at the ceiling = %d spools, want one known confirmation owing all %d destinations", len(after.spools), len(want))
			}
		})
	}
}
