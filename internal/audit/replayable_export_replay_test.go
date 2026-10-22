// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// A spooled control-plane occurrence whose row committed before the gateway
// stopped (before the exporter enqueue or the producer's reported marker) is
// offered again at the next start. The stored row alone must not end it: the
// occurrence is exported again under its id and time, with no second row and
// no second counter, and a failed export is an error so the producer offers
// it again instead of marking it reported.
func TestStoredSpooledOccurrenceIsExportedAgainAfterARestart(t *testing.T) {
	receipt := PolicyBundleReceipt{ReceiptID: testPolicyBundleID, State: PolicyBundleConfirmed,
		DeliveryID: "acme-agent:d-000913", ConfigGeneration: 3, EnforcingVersion: 5}
	offers := map[string]func(*Logger) error{
		"bundle receipt": func(logger *Logger) error {
			return logger.LogPolicyBundleReceipt("operator:root", PolicyBundle{ID: testPolicyBundleID, Version: 5}, receipt)
		},
		"trust anchors": func(logger *Logger) error {
			return logger.LogConfigChange(ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors,
				Action: "install", Outcome: ConfigChangeRefused, ReasonCode: "anchor_invalid", Actor: "os:uid:0:root"})
		},
		"credential": func(logger *Logger) error {
			return logger.LogConfigChange(ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeSecret,
				Action: "set", Outcome: ConfigChangeApplied, Actor: "os:uid:0:root", SecretName: "splunk-hec-token"})
		},
	}
	for name, offer := range offers {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.db")
			open := func() (*Store, *Logger, *testRuntimeV8Emitter) {
				store, err := NewStore(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Init(); err != nil {
					t.Fatal(err)
				}
				logger := NewLogger(store)
				runtime := newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary)
				logger.SetRuntimeV8Emitter(runtime)
				return store, logger, runtime
			}
			// The first process commits the row and stops before the
			// exporter enqueue and before the producer marks it reported.
			store, logger, first := open()
			if err := offer(logger); err != nil {
				t.Fatal(err)
			}
			_, committed := first.snapshot()
			if len(committed) != 1 {
				t.Fatalf("first process recorded %d records, want 1", len(committed))
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			store, logger, restarted := open()
			defer store.Close()
			restarted.replayErr = errors.New("exporter queue unavailable")
			if err := offer(logger); err == nil {
				t.Fatal("a stored occurrence that was not exported again was reported as recorded")
			}
			restarted.replayErr = nil
			if err := offer(logger); err != nil {
				t.Fatal(err)
			}
			exported := restarted.replaySnapshot()
			if len(exported) != 1 {
				t.Fatalf("restart exported the stored occurrence %d times, want 1", len(exported))
			}
			if exported[0].RecordID() != committed[0].RecordID() ||
				!exported[0].Timestamp().Equal(committed[0].Timestamp()) ||
				exported[0].EventName() != committed[0].EventName() {
				t.Fatalf("exported %s %s at %s, stored %s %s at %s",
					exported[0].EventName(), exported[0].RecordID(), exported[0].Timestamp(),
					committed[0].EventName(), committed[0].RecordID(), committed[0].Timestamp())
			}
			if _, records := restarted.snapshot(); len(records) != 0 {
				t.Fatalf("restart wrote %d more records", len(records))
			}
			if metrics := restarted.metricSnapshot(); len(metrics) != 0 {
				t.Fatalf("restart applied %d metrics again", len(metrics))
			}
			var rows int
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = ?`,
				committed[0].RecordID()).Scan(&rows); err != nil || rows != 1 {
				t.Fatalf("%d stored rows (%v), want 1", rows, err)
			}
		})
	}
}
