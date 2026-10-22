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

package audit

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

const testConfigChangeID = "c-01JB8Z4X6T2Q9V3M5N7P1R0S4W"

func TestLogConfigChangeRecordsEachFamily(t *testing.T) {
	sum, previous := strings.Repeat("a", 64), strings.Repeat("b", 64)
	cases := []struct {
		name    string
		change  ConfigChange
		event   string
		outcome observability.Outcome
		want    []string
		absent  []string
	}{
		{"anchors replaced", ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "install",
			Outcome: ConfigChangeApplied, Actor: "os:uid:0:root", SHA256: sum, PreviousSHA256: previous,
			KeyIDsAdded: []string{"fleet-2026-11"}, KeyIDsRemoved: []string{"fleet-2026-10"}},
			observability.TelemetryEventConfigTrustAnchorsChanged, observability.OutcomeApplied,
			[]string{`"defenseclaw.trust_anchors.sha256":"` + sum + `"`, `"defenseclaw.trust_anchors.previous_sha256":"` + previous + `"`,
				`"defenseclaw.trust_anchors.key_ids.added":["fleet-2026-11"]`, `"defenseclaw.trust_anchors.key_ids.removed":["fleet-2026-10"]`,
				`"defenseclaw.config.change.id":"` + testConfigChangeID + `"`, `"defenseclaw.admin.actor_ref":"os:uid:0:root"`},
			[]string{"defenseclaw.config.change.reason_code"}},
		{"anchors refused", ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "install",
			Outcome: ConfigChangeRefused, ReasonCode: "anchor_invalid", Actor: "os:uid:0:root", SHA256: previous},
			observability.TelemetryEventConfigTrustAnchorsChanged, observability.OutcomeRejected,
			[]string{`"defenseclaw.config.change.reason_code":"anchor_invalid"`}, nil},
		{"credential set", ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set",
			Outcome: ConfigChangeApplied, Actor: "os:uid:0:root", SecretName: "splunk-hec-token"},
			observability.TelemetryEventConfigSecretChanged, observability.OutcomeApplied,
			[]string{`"defenseclaw.secret.name":"splunk-hec-token"`, `"defenseclaw.secret.action":"set"`}, nil},
		{"credential removal failed", ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "remove",
			Outcome: ConfigChangeFailed, ReasonCode: "change_failed", Actor: "os:uid:0:root", SecretName: "splunk-hec-token"},
			observability.TelemetryEventConfigSecretChangeFailed, observability.OutcomeFailed,
			[]string{`"defenseclaw.secret.action":"remove"`, `"defenseclaw.config.change.reason_code":"change_failed"`}, nil},
		{"credential name refused", ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set",
			Outcome: ConfigChangeRefused, ReasonCode: "invalid_arguments", Actor: "os:uid:0:root"},
			observability.TelemetryEventConfigSecretChangeFailed, observability.OutcomeRejected,
			[]string{`"defenseclaw.config.change.reason_code":"invalid_arguments"`}, []string{"defenseclaw.secret.name"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			logger.SetRuntimeV8Emitter(runtime)
			if err := logger.LogConfigChange(tc.change); err != nil {
				t.Fatalf("LogConfigChange: %v", err)
			}
			_, records := runtime.snapshot()
			if len(records) != 1 || records[0].EventName() != observability.EventName(tc.event) ||
				records[0].Outcome() != tc.outcome || !records[0].Mandatory() {
				t.Fatalf("records = %d %v", len(records), records)
			}
			assertRecordMatchesRuntimeContract(t, records[0])
			encoded, err := records[0].Bytes()
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(encoded), want) {
					t.Fatalf("record lacks %s: %s", want, encoded)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(string(encoded), absent) {
					t.Fatalf("record has %s: %s", absent, encoded)
				}
			}
		})
	}
}

func TestLogConfigChangeRefusesMalformedChanges(t *testing.T) {
	logger := newTestLogger(t)
	logger.SetRuntimeV8Emitter(newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary))
	for name, change := range map[string]ConfigChange{
		"no id":            {Kind: ConfigChangeSecret, Action: "set", Outcome: ConfigChangeApplied, SecretName: "a"},
		"unknown kind":     {EventID: testConfigChangeID, Kind: "token", Action: "set", Outcome: ConfigChangeApplied},
		"failed, no code":  {EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set", Outcome: ConfigChangeFailed, SecretName: "a"},
		"applied, no name": {EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set", Outcome: ConfigChangeApplied},
		"anchor set":       {EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "set", Outcome: ConfigChangeApplied},
	} {
		if err := logger.LogConfigChange(change); err == nil {
			t.Fatalf("%s: LogConfigChange accepted %+v", name, change)
		}
	}
}

// The gateway marks a change event reported after the audit write; a
// restart between the two offers it again. The store keeps each change
// event id once, so the second offer (in the same process or after the
// restart) replays delivery without writing another local row.
func TestLogConfigChangeRecordsEachChangeOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	change := ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set",
		Outcome: ConfigChangeApplied, Actor: "os:uid:0:root", SecretName: "splunk-hec-token"}
	for run, want := range []int{1, 0} {
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
			if err := logger.LogConfigChange(change); err != nil {
				t.Fatalf("run %d offer %d: %v", run, offer, err)
			}
		}
		if _, records := runtime.snapshot(); len(records) != want {
			t.Fatalf("run %d emitted %d records, want %d", run, len(records), want)
		}
		var rows int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action = ?`,
			string(ActionConfigSecretChanged)).Scan(&rows); err != nil || rows != 1 {
			t.Fatalf("run %d: %d stored rows (%v), want 1", run, rows, err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// An audit store that cannot be read is an error, so the gateway offers the
// change again rather than marking it reported.
func TestLogConfigChangeFailsWhileTheStoreIsClosed(t *testing.T) {
	logger := newTestLogger(t)
	logger.SetRuntimeV8Emitter(newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary))
	if err := logger.store.Close(); err != nil {
		t.Fatal(err)
	}
	change := ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "install",
		Outcome: ConfigChangeRefused, ReasonCode: "lifecycle_busy", Actor: "os:uid:0:root"}
	if err := logger.LogConfigChange(change); err == nil {
		t.Fatal("LogConfigChange succeeded with the audit store closed")
	}
}
