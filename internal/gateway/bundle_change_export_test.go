// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// changeExportFixture is a bootstrapped gateway runtime with one OTLP log
// destination that can be told to refuse the change's exports (HTTP 400), the
// gateway's audit database, and one credential change event in a spool.
type changeExportFixture struct {
	capture  *hookModelV8OTLPCapture
	refusing atomic.Bool
	refused  atomic.Int64
	// slow delays the destination's answer to the change's exports.
	slow     atomic.Bool
	logger   *audit.Logger
	database *sql.DB
	dir      string
	ev       enterprisestatus.ChangeEvent
}

func newChangeExportFixture(t *testing.T) *changeExportFixture {
	t.Helper()
	f := &changeExportFixture{capture: &hookModelV8OTLPCapture{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Refuse only the change's exports: refusing every record would
		// open the destination's circuit for 30 s.
		if (f.refusing.Load() || f.slow.Load()) && r.URL.Path == "/v1/logs" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			if f.slow.Load() && bytes.Contains(body, []byte(f.ev.EventID)) {
				time.Sleep(300 * time.Millisecond)
			} else if bytes.Contains(body, []byte(f.ev.EventID)) {
				f.refused.Add(1)
				http.Error(w, "refused", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		f.capture.handler(w, r)
	}))
	t.Cleanup(server.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	fixture.sidecar.setAPIServer(&APIServer{})
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath,
		hookModelV8BootstrapRaw(fixture.dataDir, server.URL, []string{"logs"})); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	f.logger = fixture.logger
	database, err := sql.Open("sqlite", filepath.Join(fixture.dataDir, config.DefaultAuditDBName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	f.database = database
	f.dir = t.TempDir()
	f.ev = writeTestChangeEvent(t, enterprisestatus.ChangeEventsDir(f.dir), enterprisestatus.ChangeKindSecret,
		enterprisestatus.ChangeActionSet, enterprisestatus.ChangeApplied, "",
		func(ev *enterprisestatus.ChangeEvent) { ev.SecretName = "splunk-hec-token" })
	return f
}

// reporter returns a new reporter on the fixture's spool, as a gateway
// start does: it has no memory of earlier offers.
func (f *changeExportFixture) reporter() *bundleReceiptReporter {
	return &bundleReceiptReporter{receiptPath: enterprisestatus.PublicReceiptPath(f.dir),
		markerPath: filepath.Join(f.dir, bundleReceiptMarkerName), sink: f.logger,
		enforcedVersion: func() uint64 { return 0 }}
}

// exported counts the change's records the destination accepted.
func (f *changeExportFixture) exported() int {
	count := 0
	for _, record := range hookModelV8CapturedLogs(f.capture.logSnapshot()) {
		if encoded, err := protojson.Marshal(record); err == nil && strings.Contains(string(encoded), f.ev.EventID) {
			count++
		}
	}
	return count
}

func (f *changeExportFixture) storedRows(t *testing.T) int {
	t.Helper()
	var rows int
	if err := f.database.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action = ?`,
		string(audit.ActionConfigSecretChanged)).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

// pollUntil polls the reporter until cond holds.
func pollUntil(t *testing.T, reporter *bundleReceiptReporter, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		reporter.poll(t.Context())
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A change event the audit store cannot insert (the disk is full, the
// store still reads) stays in the spool and is offered at every poll. It
// reaches the remote destination only once it is stored, and only once.
// Before, every failed offer exported it again, every 5 seconds while the
// store stayed full.
func TestBundleReceiptReporterExportsAChangeOnlyOnceItIsStored(t *testing.T) {
	f := newChangeExportFixture(t)
	reporter := f.reporter()
	if _, err := f.database.Exec(`CREATE TRIGGER audit_store_full BEFORE INSERT ON audit_events
		BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		reporter.poll(t.Context())
	}
	if reporter.hasSeen(f.ev.EventID) {
		t.Fatal("a change the audit store refused was marked reported")
	}
	time.Sleep(500 * time.Millisecond) // the destination exports every 10 ms
	if n := f.exported(); n != 0 {
		t.Fatalf("a change the audit store refused was exported %d times", n)
	}
	if _, err := f.database.Exec(`DROP TRIGGER audit_store_full`); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, reporter, func() bool { return reporter.hasSeen(f.ev.EventID) })
	for range 3 {
		reporter.poll(t.Context())
	}
	time.Sleep(300 * time.Millisecond)
	if n := f.exported(); n != 1 {
		t.Fatalf("the stored change was exported %d times, want once", n)
	}
}

// A change is marked reported (which lets the change commands remove it
// from the spool) only once the remote destination acknowledged it. While
// the destination refuses it, it stays unmarked and is offered again; a
// gateway restart in between (a new reporter, the delivery state gone and
// the audit row already stored) sends the stored record again instead of
// skipping it. Before, the marker was written as soon as the local row was
// stored, and after a restart the stored row returned before any export, so
// a delivery lost in memory was never made.
func TestBundleReceiptReporterKeepsAChangeUntilTheDestinationHasIt(t *testing.T) {
	f := newChangeExportFixture(t)
	f.refusing.Store(true)
	first := f.reporter()
	pollUntil(t, first, func() bool { return f.refused.Load() >= 1 })
	if first.hasSeen(f.ev.EventID) {
		t.Fatal("a change the destination refused was marked reported")
	}
	if n := f.storedRows(t); n != 1 {
		t.Fatalf("the offers stored %d rows, want 1", n)
	}
	// A restarted gateway follows a stopped one: the first gateway's retry
	// must not still be in flight when the destination starts accepting.
	for settled := false; !settled; time.Sleep(20 * time.Millisecond) {
		settled, _ = first.changes[f.ev.EventID].delivery.Settled()
	}
	restarted := f.reporter()
	restarted.poll(t.Context())
	if restarted.hasSeen(f.ev.EventID) {
		t.Fatal("a restarted gateway marked a stored change the destination never had")
	}
	f.refusing.Store(false)
	pollUntil(t, restarted, func() bool { return restarted.hasSeen(f.ev.EventID) })
	if n := f.exported(); n != 1 {
		t.Fatalf("the destination has the change %d times, want once", n)
	}
	for range 3 {
		restarted.poll(t.Context())
	}
	time.Sleep(300 * time.Millisecond)
	if n, rows := f.exported(), f.storedRows(t); n != 1 || rows != 1 {
		t.Fatalf("after the report: exported %d, stored %d, want 1 and 1", n, rows)
	}
}

// A change is marked reported only once its audit row survives a power
// loss. The store commits with synchronous=NORMAL; LogConfigChange then
// commits once on a synchronous=FULL connection, which flushes the whole
// log. While that flush fails (here the durable write is refused), the
// change stays unmarked, whether its row was just written or found stored.
// Before, the marker was written right after the NORMAL commit.
func TestBundleReceiptReporterMarksAChangeOnlyOnceItsRowIsDurable(t *testing.T) {
	f := newChangeExportFixture(t)
	reporter := f.reporter()
	if _, err := f.database.Exec(`CREATE TRIGGER audit_flush_fails BEFORE UPDATE ON observability_store_readiness
		BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END`); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		reporter.poll(t.Context())
	}
	if reporter.hasSeen(f.ev.EventID) {
		t.Fatal("a change whose row could not be flushed was marked reported")
	}
	if n := f.storedRows(t); n != 1 {
		t.Fatalf("stored %d rows, want 1", n)
	}
	restarted := f.reporter()
	restarted.poll(t.Context())
	if restarted.hasSeen(f.ev.EventID) {
		t.Fatal("a restarted gateway marked a stored change it could not flush")
	}
	if _, err := f.database.Exec(`DROP TRIGGER audit_flush_fails`); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, restarted, func() bool { return restarted.hasSeen(f.ev.EventID) })
}

// A gateway that stops after the destination acknowledged a change but
// before its next poll marked it reported (a credential change restarts
// the gateway within seconds) must not send it again from the next
// gateway: the acknowledgement is recorded on disk as it arrives
// (GAP-0526). Before, the delivery state was in memory only and the
// restarted gateway exported the change a second time.
func TestBundleReceiptReporterDoesNotExportAnAcknowledgedChangeAgainAfterARestart(t *testing.T) {
	f := newChangeExportFixture(t)
	f.slow.Store(true)
	first := f.reporter()
	first.poll(t.Context())
	deadline := time.Now().Add(20 * time.Second)
	for settled, delivered := false, false; !settled || !delivered; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the destination never acknowledged the change")
		}
		settled, delivered = first.changes[f.ev.EventID].delivery.Settled()
	}
	if first.hasSeen(f.ev.EventID) {
		t.Fatal("the change was marked reported without a second poll")
	}
	restarted := f.reporter()
	pollUntil(t, restarted, func() bool { return restarted.hasSeen(f.ev.EventID) })
	for range 3 {
		restarted.poll(t.Context())
	}
	time.Sleep(300 * time.Millisecond)
	if n := f.exported(); n != 1 {
		t.Fatalf("the destination has the change %d times after a restart, want once", n)
	}
}
