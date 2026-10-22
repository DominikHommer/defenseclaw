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
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

var sandboxManagedInstruments = []string{
	observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals,
	observability.TelemetryInstrumentDefenseClawSandboxManagedAsks,
	observability.TelemetryInstrumentDefenseClawSandboxManagedForeignItems,
	observability.TelemetryInstrumentDefenseClawSandboxManagedProvisional,
	observability.TelemetryInstrumentDefenseClawSandboxManagedDrift,
}

// Each managed sandbox record moves its fleet counter once, with the
// driver and connector and one closed code as the only labels: never the
// guardrail profile or directory group (an operator may name either after
// one person), the person, the sandbox, the registration or the destination.
func TestSandboxManagedRecordsMoveTheirFleetCounter(t *testing.T) {
	harness := newSandboxHarness(t)
	identity, subject := testManagedIdentity(), testManagedSubject()
	// A profile assigned to one user only, and named after them.
	identity.Managed.GuardrailProfile, identity.Managed.ProfileMatch = "alice", SandboxProfileMatchUser
	identity.Managed.MatchedGroup = ""
	provisional := true
	floor := identity
	floor.Managed.Provisional = &provisional
	base := map[string]any{
		"defenseclaw.sandbox.driver":   "docker",
		"defenseclaw.connector.source": "claudecode",
	}
	with := func(extra map[string]any, drop ...string) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		for _, k := range drop {
			delete(out, k)
		}
		return out
	}
	managedOnly := SandboxIdentity{Connector: "claudecode", Driver: SandboxDriverDocker, Managed: identity.Managed}
	cases := []struct {
		name       string
		event      any
		instrument string
		want       map[string]any
	}{
		{"host run refused", SandboxHostRunRefusedEvent{Sandbox: managedOnly, Subject: subject, Reason: "required_for", Rule: "contractors"},
			observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals,
			with(map[string]any{"defenseclaw.sandbox.managed.reason": "required_for"})},
		{"sandbox unavailable refused", SandboxHostRunUnavailableEvent{Sandbox: managedOnly, Subject: subject, Reason: "no_kvm"},
			observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals,
			with(map[string]any{"defenseclaw.sandbox.managed.reason": "no_kvm"})},
		{"sandbox unavailable allowed", SandboxHostRunUnavailableEvent{Sandbox: managedOnly, Subject: subject, Reason: "no_kvm", Allowed: true},
			"", nil},
		{"access refused", SandboxAccessRefusedEvent{Sandbox: identity, Subject: subject, Host: "blocked.example.com", Port: 443, Reason: "floor_denied"},
			observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals,
			with(map[string]any{"defenseclaw.sandbox.managed.reason": "floor_denied"})},
		{"ask approved", SandboxAskDecidedEvent{Sandbox: identity, Subject: subject, ApprovalID: "ask-1", Result: SandboxApprovalApproved,
			Scope: SandboxApprovalScopeSandbox, Host: "api.example.com", Port: 443},
			observability.TelemetryInstrumentDefenseClawSandboxManagedAsks,
			with(map[string]any{"defenseclaw.approval.result": "approved"})},
		{"ask denied by the floor", SandboxAskDecidedEvent{Sandbox: identity, Subject: subject, ApprovalID: "ask-2", Result: SandboxApprovalDenied,
			Reason: "floor_denied", Host: "api.example.com", Port: 443},
			observability.TelemetryInstrumentDefenseClawSandboxManagedAsks,
			with(map[string]any{"defenseclaw.approval.result": "denied", "defenseclaw.sandbox.managed.reason": "floor_denied"})},
		{"foreign rule", SandboxPolicyForeignRuleEvent{Sandbox: identity, Subject: subject, Action: SandboxManagedRemove, Host: "evil.example.com", Port: 443, Rule: "user-added"},
			observability.TelemetryInstrumentDefenseClawSandboxManagedForeignItems,
			with(map[string]any{"defenseclaw.metric.kind": "rule", "defenseclaw.sandbox.managed.action": "remove"})},
		{"foreign sandbox", SandboxForeignSandboxEvent{Sandbox: SandboxIdentity{Name: "raw-box", Connector: "claudecode", Driver: SandboxDriverDocker, Managed: identity.Managed},
			Subject: subject, Action: SandboxManagedStop},
			observability.TelemetryInstrumentDefenseClawSandboxManagedForeignItems,
			with(map[string]any{"defenseclaw.metric.kind": "sandbox", "defenseclaw.sandbox.managed.action": "stop"})},
		{"foreign container", SandboxForeignContainerEvent{Sandbox: SandboxIdentity{Name: "claude-dev", Managed: identity.Managed}, Subject: subject},
			observability.TelemetryInstrumentDefenseClawSandboxManagedForeignItems,
			with(map[string]any{"defenseclaw.metric.kind": "container", "defenseclaw.sandbox.managed.action": "alert"},
				"defenseclaw.sandbox.driver", "defenseclaw.connector.source")},
		{"resolved on the offline floor", SandboxPolicyResolvedEvent{Sandbox: floor, Subject: subject, Reason: "offline_floor"},
			observability.TelemetryInstrumentDefenseClawSandboxManagedProvisional,
			with(map[string]any{"defenseclaw.metric.result": "provisional"})},
		{"resolved, not provisional", SandboxPolicyResolvedEvent{Sandbox: identity, Subject: subject}, "", nil},
		{"provisional lookup resolved", SandboxPolicyRematchedEvent{Sandbox: identity, Subject: subject, Reason: SandboxRematchLookupResolved},
			observability.TelemetryInstrumentDefenseClawSandboxManagedProvisional,
			with(map[string]any{"defenseclaw.metric.result": "resolved"})},
		{"generation re-match", SandboxPolicyRematchedEvent{Sandbox: identity, Subject: subject, Reason: SandboxRematchGeneration}, "", nil},
		{"settings drift", SandboxSettingsDriftEvent{Sandbox: managedOnly, Subject: subject, Field: "compute_driver"},
			observability.TelemetryInstrumentDefenseClawSandboxManagedDrift,
			with(map[string]any{"defenseclaw.openshell.settings.field": "compute_driver"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := recordManagedEvent(context.Background(), recorder, tc.event); err != nil {
				t.Fatal(err)
			}
			for _, instrument := range sandboxManagedInstruments {
				got := sandboxMetrics(t, runtime, instrument)
				if instrument != tc.instrument {
					if len(got) != 0 {
						t.Fatalf("%s moved %d times; want only %q", instrument, len(got), tc.instrument)
					}
					continue
				}
				if len(got) != 1 || sandboxMetricValue(t, got[0]) != 1 {
					t.Fatalf("%s points=%d, want one increment", instrument, len(got))
				}
				attributes := metricAttributes(t, got[0])
				if !reflect.DeepEqual(attributes, tc.want) {
					t.Fatalf("%s attributes=%#v want %#v", instrument, attributes, tc.want)
				}
				for key, value := range attributes {
					if value == "alice" {
						t.Fatalf("%s label %q carries the user-named profile or the user", instrument, key)
					}
					for _, private := range []string{"guardrail.profile", "group", "user", "subject", "principal", "registration", "sandbox.name", "sandbox.id", "server.", "host."} {
						if strings.Contains(key, private) {
							t.Fatalf("%s carries the per-person or per-sandbox label %q", instrument, key)
						}
					}
				}
			}
		})
	}
}

// A reason or OpenShell setting key is a counter value only when the code
// defines it. The daemon that reports a drift or an access refusal runs as
// the user, so any value it posts, such as a user's name, counts as other on
// every managed counter that has a reason or a setting key, and only the
// access-controlled record keeps it.
func TestSandboxManagedCounterCodesComeFromTheCode(t *testing.T) {
	harness := newSandboxHarness(t)
	identity, subject := testManagedIdentity(), testManagedSubject()
	managedOnly := SandboxIdentity{Connector: "claudecode", Driver: SandboxDriverDocker, Managed: identity.Managed}
	const reasonKey, fieldKey = "defenseclaw.sandbox.managed.reason", "defenseclaw.openshell.settings.field"
	type counterCase struct {
		name, instrument, key string
		event                 any
	}
	casesFor := func(value string) []counterCase {
		return []counterCase{
			{"settings drift", observability.TelemetryInstrumentDefenseClawSandboxManagedDrift, fieldKey,
				SandboxSettingsDriftEvent{Sandbox: managedOnly, Subject: subject, Field: value}},
			{"access refused", observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals, reasonKey,
				SandboxAccessRefusedEvent{Sandbox: identity, Subject: subject, Host: "blocked.example.com", Port: 443, Reason: value}},
			{"host run refused", observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals, reasonKey,
				SandboxHostRunRefusedEvent{Sandbox: managedOnly, Subject: subject, Reason: value}},
			{"host run unavailable", observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals, reasonKey,
				SandboxHostRunUnavailableEvent{Sandbox: managedOnly, Subject: subject, Reason: value}},
			{"ask decided", observability.TelemetryInstrumentDefenseClawSandboxManagedAsks, reasonKey,
				SandboxAskDecidedEvent{Sandbox: identity, Subject: subject, ApprovalID: "ask-1", Result: SandboxApprovalDenied,
					Reason: value, Host: "api.example.com", Port: 443}},
		}
	}
	counted := func(t *testing.T, tc counterCase) (string, string) {
		t.Helper()
		runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
		if err := recordManagedEvent(context.Background(), recorder, tc.event); err != nil {
			t.Fatal(err)
		}
		points := sandboxMetrics(t, runtime, tc.instrument)
		if len(points) != 1 {
			t.Fatalf("%s points=%d, want one", tc.instrument, len(points))
		}
		label, _ := metricAttributes(t, points[0])[tc.key].(string)
		_, record := onlySandboxRecord(t, runtime)
		encoded, err := record.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		return label, string(encoded)
	}
	// Person-like and varying values: one series (other), whatever was posted.
	for _, value := range []string{"alice", "bob", "ent_alice", "alice_smith", "u1001", "compute_driver2", "required_for_alice", "other"} {
		for _, tc := range casesFor(value) {
			t.Run(tc.name+"/"+value, func(t *testing.T) {
				label, record := counted(t, tc)
				if label != SandboxManagedMetricOther {
					t.Fatalf("%s %s=%q, want %q", tc.instrument, tc.key, label, SandboxManagedMetricOther)
				}
				if want := `"` + tc.key + `":"` + value + `"`; !strings.Contains(record, want) {
					t.Fatalf("the record lost the posted value %s: %s", want, record)
				}
			})
		}
	}
	// A dotted key fits the setting key pattern only.
	for _, value := range []string{"home.alice", "users.alice.profile"} {
		tc := casesFor(value)[0]
		if label, _ := counted(t, tc); label != SandboxManagedMetricOther {
			t.Fatalf("drift field %q counted as %q", value, label)
		}
	}
	// Every code-defined value is its own counter value.
	for code := range sandboxManagedMetricReasons {
		for _, tc := range casesFor(code)[1:] {
			if label, _ := counted(t, tc); label != code {
				t.Fatalf("%s reason %q counted as %q", tc.name, code, label)
			}
		}
	}
	for field := range sandboxManagedMetricSettingsFields {
		if label, _ := counted(t, casesFor(field)[0]); label != field {
			t.Fatalf("drift field %q counted as %q", field, label)
		}
	}
}
