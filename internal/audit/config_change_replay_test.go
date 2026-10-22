// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// A change's record is built from the change alone, as its spool event
// holds it: on every offer, in this process or after a restart (another
// run id, sidecar id and binary), it has the change's stable record id, the
// change's time as its time, and the same outcome and change attributes,
// and the stored row has the change's time too. The audit row and each
// remote destination are sinks of the same record. Before, the record and
// its row took the time of the first offer, and a later process could send
// the stored record only when it rebuilt it exactly from the row.
func TestLogConfigChangeRecordIsBuiltFromTheChangeAlone(t *testing.T) {
	previousRun, previousSidecar := gatewaylog.ProcessRunID(), ProcessAgentInstanceID()
	previousBinary := version.Current().BinaryVersion
	t.Cleanup(func() {
		gatewaylog.SetProcessRunID(previousRun)
		SetProcessAgentInstanceID(previousSidecar)
		version.SetBinaryVersion(previousBinary)
	})
	const changedAt = "2026-10-20T08:30:00.123Z"
	at, err := time.Parse(time.RFC3339Nano, changedAt)
	if err != nil {
		t.Fatal(err)
	}
	sum, previous := strings.Repeat("a", 64), strings.Repeat("b", 64)
	change := ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "install",
		Outcome: ConfigChangeApplied, Actor: "os:uid:0:root", ChangedAt: changedAt, SHA256: sum, PreviousSHA256: previous,
		KeyIDsAdded: []string{"fleet-2026-11"}, KeyIDsRemoved: []string{"fleet-2026-10"}}
	recordID := stableOccurrenceID("config.change", change.EventID)
	path := filepath.Join(t.TempDir(), "audit.db")
	var records []observability.Record
	for _, process := range []struct{ run, sidecar, binary string }{
		{"run-before-restart", "sidecar-before-restart", "1.0.4-dev.1"},
		{"run-after-restart", "sidecar-after-restart", "1.0.4-dev.2"},
	} {
		gatewaylog.SetProcessRunID(process.run)
		SetProcessAgentInstanceID(process.sidecar)
		version.SetBinaryVersion(process.binary)
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
		for offer := 0; offer < 2; offer++ {
			if err := logger.LogConfigChange(change, nil); err != nil {
				t.Fatalf("%s offer %d: %v", process.run, offer, err)
			}
		}
		_, emitted := runtime.snapshot()
		records = append(records, emitted...)
		var stamp string
		if err := store.db.QueryRow(`SELECT timestamp FROM audit_events WHERE id = ?`, recordID).Scan(&stamp); err != nil {
			t.Fatal(err)
		}
		if stored, err := time.Parse(time.RFC3339Nano, stamp); err != nil || !stored.Equal(at) {
			t.Fatalf("%s: the stored row has the time %q, want the change's %s", process.run, stamp, changedAt)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if len(records) != 4 {
		t.Fatalf("emitted %d records, want one per offer", len(records))
	}
	for index, record := range records {
		if record.RecordID() != recordID || !record.Timestamp().Equal(at) || record.Outcome() != observability.OutcomeApplied ||
			record.EventName() != observability.EventName(observability.TelemetryEventConfigTrustAnchorsChanged) {
			t.Fatalf("offer %d: record %s at %s outcome %s event %s, want %s at %s, applied",
				index, record.RecordID(), record.Timestamp(), record.Outcome(), record.EventName(), recordID, changedAt)
		}
		encoded, err := record.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range []string{
			`"defenseclaw.config.change.id":"` + testConfigChangeID + `"`,
			`"defenseclaw.trust_anchors.sha256":"` + sum + `"`,
			`"defenseclaw.trust_anchors.previous_sha256":"` + previous + `"`,
			`"defenseclaw.trust_anchors.key_ids.added":["fleet-2026-11"]`,
			`"defenseclaw.admin.actor_ref":"os:uid:0:root"`,
		} {
			if !strings.Contains(string(encoded), part) {
				t.Fatalf("offer %d: the record lacks %s: %s", index, part, encoded)
			}
		}
	}
}
