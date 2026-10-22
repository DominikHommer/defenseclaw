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
	"fmt"
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
// restart) writes nothing and succeeds.
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

// A change is offered again until the audit store records it, so the
// runtime must export it only after its local write: LogConfigChange marks
// its occurrence for every kind and outcome, an ordinary activity is not
// marked and is still exported while the store is down (GAP-1536).
func TestLogConfigChangeIsExportedOnlyAfterTheLocalWrite(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	ids := []string{testConfigChangeID, "c-01JB8Z4X6T2Q9V3M5N7P1R0S4X", "c-01JB8Z4X6T2Q9V3M5N7P1R0S4Y"}
	for index, change := range []ConfigChange{
		{Kind: ConfigChangeTrustAnchors, Action: "install", Outcome: ConfigChangeApplied, SHA256: strings.Repeat("a", 64)},
		{Kind: ConfigChangeSecret, Action: "set", Outcome: ConfigChangeApplied, SecretName: "splunk-hec-token"},
		{Kind: ConfigChangeSecret, Action: "remove", Outcome: ConfigChangeFailed, ReasonCode: "interrupted", SecretName: "otlp-token"},
	} {
		change.EventID, change.Actor = ids[index], "os:uid:0:root"
		if err := logger.LogConfigChange(change); err != nil {
			t.Fatalf("LogConfigChange %d: %v", index, err)
		}
	}
	if err := logger.LogActivity(ActivityInput{
		Actor: "watcher", Action: ActionPolicyReload, TargetType: "policy", TargetID: "default",
	}); err != nil {
		t.Fatalf("LogActivity: %v", err)
	}
	runtime.mu.Lock()
	marks := append([]bool(nil), runtime.exportAfterWrite...)
	runtime.mu.Unlock()
	if want := []bool{true, true, true, false}; fmt.Sprint(marks) != fmt.Sprint(want) {
		t.Fatalf("export-after-local-write marks = %v, want %v", marks, want)
	}
}

// The activity counters of a change carry one fixed actor label for every
// kind and outcome. The OS account (a Windows administrator SID and name,
// or a uid and user name) stays in the audit record and enters no metric
// label. Before, it was the actor label of defenseclaw.activity.total and
// defenseclaw.activity.diff_entries.
func TestLogConfigChangeKeepsTheAccountOffTheCounters(t *testing.T) {
	const sid, account = "S-1-5-21-1004336348-1177238915-682003330-500", "CORP/Administrator"
	for name, change := range map[string]ConfigChange{
		"anchors installed": {Kind: ConfigChangeTrustAnchors, Action: "install", Outcome: ConfigChangeApplied,
			SHA256: strings.Repeat("a", 64)},
		"anchors refused": {Kind: ConfigChangeTrustAnchors, Action: "install", Outcome: ConfigChangeRefused,
			ReasonCode: "anchor_invalid"},
		"credential set": {Kind: ConfigChangeSecret, Action: "set", Outcome: ConfigChangeApplied,
			SecretName: "splunk-hec-token"},
		"credential removal interrupted": {Kind: ConfigChangeSecret, Action: "remove", Outcome: ConfigChangeFailed,
			ReasonCode: "interrupted", SecretName: "otlp-token"},
		"credential name refused": {Kind: ConfigChangeSecret, Action: "set", Outcome: ConfigChangeRefused,
			ReasonCode: "invalid_arguments"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, actor := range []string{"os:sid:" + sid + ":" + account, "os:uid:0:root"} {
				change.EventID, change.Actor = testConfigChangeID, actor
				logger := newTestLogger(t)
				runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
				logger.SetRuntimeV8Emitter(runtime)
				if err := logger.LogConfigChange(change); err != nil {
					t.Fatalf("LogConfigChange: %v", err)
				}
				_, records := runtime.snapshot()
				if len(records) != 1 {
					t.Fatalf("records = %d", len(records))
				}
				if encoded, err := records[0].Bytes(); err != nil ||
					!strings.Contains(string(encoded), `"defenseclaw.admin.actor_ref":"`+actor+`"`) {
					t.Fatalf("the audit record lost the actor %s: %s %v", actor, encoded, err)
				}
				activity := 0
				for _, metric := range runtime.metricSnapshot() {
					encoded, err := metric.Bytes()
					if err != nil {
						t.Fatal(err)
					}
					for _, part := range []string{sid, account, "Administrator", "root", "uid:0", actor} {
						if strings.Contains(string(encoded), part) {
							t.Fatalf("metric %s carries %q: %s", metric.EventName(), part, encoded)
						}
					}
					switch metric.EventName() {
					case observability.EventName(observability.TelemetryInstrumentDefenseClawActivityTotal),
						observability.EventName(observability.TelemetryInstrumentDefenseClawActivityDiffEntries):
						activity++
						if !strings.Contains(string(encoded), `"defenseclaw.metric.actor":"`+configChangeMetricActor+`"`) {
							t.Fatalf("metric %s actor label is not %s: %s", metric.EventName(), configChangeMetricActor, encoded)
						}
					}
				}
				if activity != 2 {
					t.Fatalf("activity counters = %d, want 2", activity)
				}
			}
		})
	}
}
