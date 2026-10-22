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
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func writeTestChangeEvent(t *testing.T, dir string, kind, action, outcome, code string, edit func(*enterprisestatus.ChangeEvent)) enterprisestatus.ChangeEvent {
	t.Helper()
	ev, err := enterprisestatus.NewChangeEvent(kind, action, outcome, code)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(&ev)
	}
	if err := (enterprisestatus.ChangeSpool{Dir: dir, StateDir: t.TempDir()}).Write(ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// A change made while the gateway was stopped waits in the spool and is
// reported once at the next start; a restart does not report it again.
func TestBundleReceiptReporterReportsEachChangeEventOnce(t *testing.T) {
	dir := t.TempDir()
	receipts := enterprisestatus.PublicReceiptPath(dir)
	spool := enterprisestatus.ChangeEventsDir(dir)
	sink := &fakeBundleReceiptSink{}
	newReporter := func() *bundleReceiptReporter {
		return &bundleReceiptReporter{receiptPath: receipts, markerPath: filepath.Join(dir, bundleReceiptMarkerName),
			sink: sink, enforcedVersion: func() uint64 { return 0 }}
	}
	anchors := writeTestChangeEvent(t, spool, enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall,
		enterprisestatus.ChangeApplied, "", func(ev *enterprisestatus.ChangeEvent) {
			ev.SHA256, ev.KeyIDsAdded = strings.Repeat("a", 64), []string{"fleet-2026-11"}
		})
	secret := writeTestChangeEvent(t, spool, enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionSet,
		enterprisestatus.ChangeApplied, "", func(ev *enterprisestatus.ChangeEvent) { ev.SecretName = "splunk-hec-token" })
	reporter := newReporter()
	reporter.poll(context.Background())
	reporter.poll(context.Background())
	newReporter().poll(context.Background())
	if len(sink.changes) != 2 || sink.changes[0].EventID != anchors.EventID || sink.changes[1].EventID != secret.EventID ||
		sink.changes[0].SHA256 != anchors.SHA256 || sink.changes[0].KeyIDsAdded[0] != "fleet-2026-11" ||
		sink.changes[1].SecretName != "splunk-hec-token" || sink.changes[1].Actor == "" {
		t.Fatalf("changes = %+v", sink.changes)
	}
	failed := writeTestChangeEvent(t, spool, enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionSet,
		enterprisestatus.ChangeRefused, "invalid_arguments", nil)
	newReporter().poll(context.Background())
	if len(sink.changes) != 3 || sink.changes[2].EventID != failed.EventID || sink.changes[2].ReasonCode != "invalid_arguments" ||
		sink.changes[2].SecretName != "" {
		t.Fatalf("changes = %+v", sink.changes)
	}
}

// A file in the spool that does not validate is never reported. An event
// the audit logger refuses is never marked reported, however often it is
// refused: it is reported once the logger takes it, and only once.
func TestBundleReceiptReporterKeepsRefusedChangeEventsUntilRecorded(t *testing.T) {
	dir := t.TempDir()
	spool := enterprisestatus.ChangeEventsDir(dir)
	if err := os.MkdirAll(spool, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool, "c-01JB8Z4X6T2Q9V3M5N7P1R0S4W.json"),
		[]byte(`{"schema_version":1,"event_id":"c-01JB8Z4X6T2Q9V3M5N7P1R0S4W","kind":"token","action":"set","outcome":"applied","time":"2026-10-21T10:00:00Z","secret_name":"x"}`+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	sink := &fakeBundleReceiptSink{changeErr: errors.New("audit store unavailable")}
	reporter := &bundleReceiptReporter{receiptPath: enterprisestatus.PublicReceiptPath(dir),
		markerPath: filepath.Join(dir, bundleReceiptMarkerName), sink: sink, enforcedVersion: func() uint64 { return 0 }}
	ev := writeTestChangeEvent(t, spool, enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionRemove,
		enterprisestatus.ChangeApplied, "", func(ev *enterprisestatus.ChangeEvent) { ev.SecretName = "otlp-token" })
	for range 36 { // More than the retired receipt retry cap.
		reporter.poll(context.Background())
	}
	if reporter.hasSeen(ev.EventID) || enterprisestatus.ChangeReported(dir, ev.EventID) {
		t.Fatal("a change event the audit logger refused was marked reported")
	}
	sink.changeErr = nil
	reporter.poll(context.Background())
	reporter.poll(context.Background())
	if len(sink.changes) != 1 || sink.changes[0].EventID != ev.EventID {
		t.Fatalf("changes = %+v, want the refused event once", sink.changes)
	}
	if !enterprisestatus.ChangeReported(dir, ev.EventID) {
		t.Fatal("the recorded event has no marker the change commands can read")
	}
}

// The markers stay where earlier builds wrote them (<data>/bundle-receipt.reported.d),
// so an upgraded gateway does not report its receipts again and the change
// commands read the same folder.
func TestBundleReceiptReporterMarkersFolderIsStable(t *testing.T) {
	dir := t.TempDir()
	reporter := &bundleReceiptReporter{markerPath: filepath.Join(dir, bundleReceiptMarkerName)}
	if got, want := reporter.seenDir(), filepath.Join(dir, bundleReceiptMarkerName)+".d"; got != want {
		t.Fatalf("markers folder = %s, want %s", got, want)
	}
}
