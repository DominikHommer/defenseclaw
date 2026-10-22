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
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// A change event the audit store cannot insert (the disk is full, the
// store still reads) stays in the spool and is offered at every poll. It
// reaches the remote destination only once it is stored, and only once.
// Before, every failed offer exported it again, every 5 seconds while the
// store stayed full.
func TestBundleReceiptReporterExportsAChangeOnlyOnceItIsStored(t *testing.T) {
	capture := &hookModelV8OTLPCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	t.Cleanup(server.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	fixture.sidecar.setAPIServer(&APIServer{})
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath,
		hookModelV8BootstrapRaw(fixture.dataDir, server.URL, []string{"logs"})); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	dir := t.TempDir()
	ev := writeTestChangeEvent(t, enterprisestatus.ChangeEventsDir(dir), enterprisestatus.ChangeKindSecret,
		enterprisestatus.ChangeActionSet, enterprisestatus.ChangeApplied, "",
		func(ev *enterprisestatus.ChangeEvent) { ev.SecretName = "splunk-hec-token" })
	reporter := &bundleReceiptReporter{receiptPath: enterprisestatus.PublicReceiptPath(dir),
		markerPath: filepath.Join(dir, bundleReceiptMarkerName), sink: fixture.logger,
		enforcedVersion: func() uint64 { return 0 }}
	exported := func() int {
		count := 0
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			if encoded, err := protojson.Marshal(record); err == nil && strings.Contains(string(encoded), ev.EventID) {
				count++
			}
		}
		return count
	}
	database, err := sql.Open("sqlite", filepath.Join(fixture.dataDir, config.DefaultAuditDBName))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`CREATE TRIGGER audit_store_full BEFORE INSERT ON audit_events
		BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		reporter.poll(t.Context())
	}
	if reporter.hasSeen(ev.EventID) {
		t.Fatal("a change the audit store refused was marked reported")
	}
	time.Sleep(500 * time.Millisecond) // the destination exports every 10 ms
	if n := exported(); n != 0 {
		t.Fatalf("a change the audit store refused was exported %d times", n)
	}
	if _, err := database.Exec(`DROP TRIGGER audit_store_full`); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		reporter.poll(t.Context())
	}
	if !reporter.hasSeen(ev.EventID) {
		t.Fatal("the stored change was not marked reported")
	}
	eventuallyTrue(t, func() bool { return exported() >= 1 })
	time.Sleep(300 * time.Millisecond)
	if n := exported(); n != 1 {
		t.Fatalf("the stored change was exported %d times, want once", n)
	}
}
