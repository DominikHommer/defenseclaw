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

//go:build linux || darwin

package gateway

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// counterCapture builds every record and companion counter it is given.
type counterCapture struct {
	mu      sync.Mutex
	records []string
	metrics []observability.Record
}

func counterCaptureContext() audit.RuntimeV8BuildContext {
	return audit.RuntimeV8BuildContext{ConfigGeneration: 1, ConfigDigest: strings.Repeat("a", 64)}
}

func (c *counterCapture) EmitRuntimeV8(
	_ context.Context, _ router.Metadata, build audit.RuntimeV8Builder,
) (audit.RuntimeV8EmitOutcome, error) {
	record, err := build(counterCaptureContext(), router.AdmissionOrdinary)
	if err != nil {
		return audit.RuntimeV8EmitOutcome{}, err
	}
	encoded, err := record.MarshalJSON()
	if err != nil {
		return audit.RuntimeV8EmitOutcome{}, err
	}
	c.mu.Lock()
	c.records = append(c.records, string(encoded))
	c.mu.Unlock()
	return audit.RuntimeV8EmitOutcome{Admission: router.AdmissionOrdinary, LocalPersisted: true}, nil
}

func (c *counterCapture) RecordRuntimeV8GeneratedMetricBatch(_ context.Context, metrics []audit.RuntimeV8GeneratedMetric) error {
	for _, metric := range metrics {
		record, err := metric.Build(counterCaptureContext())
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.metrics = append(c.metrics, record)
		c.mu.Unlock()
	}
	return nil
}

// labels are the attribute values of key on the captured points of
// instrument.
func (c *counterCapture) labels(t *testing.T, instrument, key string) []string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, record := range c.metrics {
		if record.EventName() != observability.EventName(instrument) {
			continue
		}
		data, present := record.InstrumentData()
		if !present {
			t.Fatal("metric instrument data is absent")
		}
		object, err := data.Object()
		if err != nil {
			t.Fatal(err)
		}
		attributes, _ := object["attributes"].(map[string]any)
		value, _ := attributes[key].(string)
		out = append(out, value)
	}
	return out
}

// A managed account's daemon posts its settings_drift field and its
// access_refused reason, so either is the user's claim: through the events
// route, a person-like or varying value counts as other on the managed
// counters and never becomes a Prometheus series of its own. The
// access-controlled record keeps the value, and a code the product defines
// still counts as itself.
func TestManagedSandboxCounterLabelsAreCodeDefined(t *testing.T) {
	f, _ := managedTelemetryFixture(t)
	id := boundRegistration(t, f, sbxAlice, 1)
	capture := &counterCapture{}
	f.api.logger.SetRuntimeV8Emitter(capture)
	now := time.Now().UTC()
	claimed := []string{"alice", "ent_alice", "alice_smith", "bob", "u1001", "compute_driver_alice", "required_for_bob"}
	var events []sandboxrelay.Event
	for i, value := range claimed {
		at := now.Add(time.Duration(i) * time.Millisecond)
		events = append(events,
			telemetryEvent(t, sandboxrelay.EventSettingsDrift, at, map[string]any{"field": value}),
			telemetryEvent(t, sandboxrelay.EventAccessRefused, at, map[string]any{
				"sandbox": "dc-claude-1", "host": "blocked.example.com", "port": 443, "rule": "org-floor", "reason": value}))
	}
	events = append(events,
		telemetryEvent(t, sandboxrelay.EventSettingsDrift, now, map[string]any{"field": "compute_driver"}),
		telemetryEvent(t, sandboxrelay.EventAccessRefused, now, map[string]any{
			"sandbox": "dc-claude-1", "host": "blocked.example.com", "port": 443, "rule": "org-floor", "reason": "egress_proxy"}))
	if resp := postEvents(f, sbxAlice, id, events...); resp.Code != http.StatusAccepted {
		t.Fatalf("events returned %d: %s", resp.Code, resp.Body.String())
	}
	for _, check := range []struct {
		instrument, key, defined string
	}{
		{observability.TelemetryInstrumentDefenseClawSandboxManagedDrift, "defenseclaw.openshell.settings.field", "compute_driver"},
		{observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals, "defenseclaw.sandbox.managed.reason", "egress_proxy"},
	} {
		got := capture.labels(t, check.instrument, check.key)
		counts := map[string]int{}
		for _, value := range got {
			counts[value]++
		}
		if len(got) != len(claimed)+1 || counts[audit.SandboxManagedMetricOther] != len(claimed) || counts[check.defined] != 1 {
			t.Fatalf("%s %s values = %v, want %d x %q and one %q", check.instrument, check.key, got,
				len(claimed), audit.SandboxManagedMetricOther, check.defined)
		}
	}
	capture.mu.Lock()
	records := strings.Join(capture.records, "\n")
	capture.mu.Unlock()
	for _, value := range claimed {
		for _, key := range []string{"defenseclaw.openshell.settings.field", "defenseclaw.sandbox.managed.reason"} {
			if want := `"` + key + `":"` + value + `"`; !strings.Contains(records, want) {
				t.Errorf("no record keeps %s", want)
			}
		}
	}
}

// Every reason code and setting key the gateway, the daemon and the
// require-sandbox gate produce is a value of the managed counters, so a new
// one is added to the allow-list instead of counting as other.
func TestManagedSandboxProducedCodesAreCounterValues(t *testing.T) {
	reasons := []string{requireSandboxReasonRequired, sandboxAccountBusyCode, sandboxAskReasonFloorDenied,
		sandboxCodeNoDockerGroup, sandboxCodeNoKVMGroup, sandboxUnavailable("not a registered reason").Code}
	for _, code := range sandboxUnavailableCodes {
		reasons = append(reasons, code)
	}
	for _, reason := range []string{openshell.DriverReasonKVMMissing, openshell.DriverReasonCPUVirtualization,
		openshell.DriverReasonKVMAccess, "another reason"} {
		reasons = append(reasons, sandboxVMRequired(reason).Code)
	}
	for _, code := range reasons {
		if got := audit.SandboxManagedMetricReason(code); got != code {
			t.Errorf("reason %q counts as %q", code, got)
		}
	}
	state := &openshell.GatewayConfigState{}
	drift := state.Drift(openshell.RenderedGateway{BindAddress: "127.0.0.1:1", ComputeDriver: openshell.DriverVM, VMSandboxUID: 4242, VMSandboxGID: 4242})
	drift = append(drift, state.Drift(openshell.RenderedGateway{BindAddress: "127.0.0.1:1", ComputeDriver: openshell.DriverDocker})...)
	fields := []string{"gateway configuration", "gateway command"}
	for _, d := range drift {
		fields = append(fields, d.Field)
	}
	if len(drift) < 5 {
		t.Fatalf("drift fixture found %d settings: %v", len(drift), drift)
	}
	for _, field := range fields {
		key := driftEventField(field)
		if got := audit.SandboxManagedMetricSettingsField(key); got != key {
			t.Errorf("setting %q (%q) counts as %q", field, key, got)
		}
	}
}
