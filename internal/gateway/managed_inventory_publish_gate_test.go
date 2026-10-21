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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// managedGateEmitter is a capture that can also fail, so the "an emit error must
// not record a digest" path is reachable.
type managedGateEmitter struct {
	endpointInventoryCapture
	failEventName observability.EventName
	// managedRejectSource names one ai.discovery collection whose records the
	// managed AI Defense projection cannot build. Those emits still succeed
	// locally and return a nil error — the failure is visible only through the
	// outcome, which is exactly the shape the gate must not mistake for delivery.
	managedRejectSource string
}

func (emitter *managedGateEmitter) Emit(
	ctx context.Context,
	metadata router.Metadata,
	build observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	if emitter.failEventName != "" {
		record, err := build(observabilityruntime.EmitContext{}, router.AdmissionOrdinary)
		if err == nil && record.EventName() == emitter.failEventName {
			return pipeline.LocalLogOutcome{}, errors.New("emit rejected")
		}
	}
	outcome, err := emitter.endpointInventoryCapture.Emit(ctx, metadata, build)
	if err == nil && emitter.managedRejectSource != "" &&
		managedGateRecordSource(emitter.lastRecord()) == emitter.managedRejectSource {
		return pipeline.NewManagedOptionalFailureOutcomeForTest(
			pipeline.OptionalFailureProjection,
		), nil
	}
	return outcome, err
}

// lastRecord returns the record the capture just appended, so the fake can decide
// per record without re-running the builder.
func (capture *endpointInventoryCapture) lastRecord() observability.Record {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.records) == 0 {
		return observability.Record{}
	}
	return capture.records[len(capture.records)-1]
}

// managedGateRecordSource reads defenseclaw.ai.discovery.source without a
// *testing.T so the fake emitter can use it inline.
func managedGateRecordSource(record observability.Record) string {
	body, present := record.Body()
	if !present {
		return ""
	}
	object, err := body.Object()
	if err != nil {
		return ""
	}
	source, _ := object[observability.TelemetryAttributeDefenseClawAIDiscoverySource].(string)
	return source
}

// managedGateScanCounts counts the endpoint-inventory records per collection so a
// test can distinguish "collection republished in full" from "silent".
func managedGateScanCounts(records []observability.Record) map[string]int {
	counts := map[string]int{}
	for _, record := range records {
		if record.EventName() == "ai.discovery.completed" {
			counts["signals_summary"]++
			continue
		}
		counts[string(record.EventName())]++
	}
	return counts
}

func managedGateReport(scanID string, skills ...string) inventory.AIDiscoveryReport {
	report := inventory.AIDiscoveryReport{
		Summary: inventory.AIDiscoverySummary{
			ScanID: scanID, Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
			TotalSignals: len(skills), ActiveSignals: len(skills),
		},
	}
	for _, skill := range skills {
		report.Signals = append(report.Signals, inventory.AISignal{
			SignalID: "ai-skill-" + skill, SignatureID: "skill", Category: inventory.SignalSkill,
			Vendor: "local", Product: skill, Confidence: .9, State: inventory.AIStateSeen,
			Detector: "skill_dir", EvidenceHash: "evidence-" + skill,
			Basenames: []string{skill},
			// skill_entry is the evidence type discoveredEntriesFromReport
			// enumerates; a bare directory row would produce no component.
			Evidence: []inventory.AIEvidence{{
				Type: "skill_entry", Basename: skill, PathHash: "hash-" + skill,
				Quality: 1, Origin: "user",
			}},
		})
	}
	return report
}

// managedGateFanout reproduces inventory.fanoutReport's publisher order for one
// scan: the per-signal observer first, then the endpoint-inventory hook. The
// order is load-bearing — the signals path establishes the memoized bundle
// decision and the endpoint hook, which alone carries all six collections,
// stamps the daily bundle clock at the end of the cycle.
func managedGateFanout(
	t *testing.T,
	gate *managedInventoryPublishState,
	report inventory.AIDiscoveryReport,
) (map[string]int, map[string]int) {
	t.Helper()
	signalsCapture := &endpointInventoryCapture{}
	adapter := &aiDiscoveryV8Adapter{runtime: signalsCapture, publishGate: gate}
	if err := adapter.EmitReport(t.Context(), report, nil); err != nil {
		t.Fatal(err)
	}
	endpointCapture := &endpointInventoryCapture{}
	cfg := &config.Config{Claw: config.ClawConfig{Mode: config.ClawMode("codex")}}
	if err := emitEndpointInventory(
		t.Context(), cfg, connector.NewDefaultRegistry(), endpointCapture, false, &report, gate,
	); err != nil {
		t.Fatal(err)
	}
	return managedGateScanCounts(signalsCapture.snapshot()),
		managedGateScanCounts(endpointCapture.snapshot())
}

// TestAIDiscoveryV8SignalsGateManagedSteadyState: the per-signal snapshot is
// suppressed in managed steady state, but the per-scan liveness summary is not.
func TestAIDiscoveryV8SignalsGateManagedSteadyState(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)

	signals, endpoint := managedGateFanout(t, gate, managedGateReport("scan-1", "alpha"))
	if signals["signals_summary"] != 1 || signals["ai_component.observed"] != 1 {
		t.Fatalf("baseline signals counts=%v", signals)
	}
	if len(endpoint) == 0 {
		t.Fatal("baseline endpoint bundle published nothing")
	}

	signals, endpoint = managedGateFanout(t, gate, managedGateReport("scan-2", "alpha"))
	if signals["signals_summary"] != 1 {
		t.Fatalf("liveness summary was suppressed: %v", signals)
	}
	if signals["ai_component.observed"] != 0 {
		t.Fatalf("steady-state per-signal records were published: %v", signals)
	}
	if len(endpoint) != 0 {
		t.Fatalf("steady-state endpoint collections were published: %v", endpoint)
	}

	// A lifecycle change republishes the whole snapshot, `seen` rows included.
	changed := managedGateReport("scan-3", "alpha", "beta")
	changed.Signals[1].State = inventory.AIStateNew
	changed.Summary.NewSignals = 1
	signals, _ = managedGateFanout(t, gate, changed)
	if signals["ai_component.discovered"] != 1 || signals["ai_component.observed"] != 1 {
		t.Fatalf("changed scan did not republish the full snapshot: %v", signals)
	}

	// The cycle after the change settles back into silence: the lifecycle-change
	// publish must also have fingerprinted the scan.
	signals, endpoint = managedGateFanout(t, gate, managedGateReport("scan-4", "alpha", "beta"))
	if signals["ai_component.observed"] != 0 {
		t.Fatalf("cycle after a lifecycle change republished signals: %v", signals)
	}
	if len(endpoint) != 0 {
		t.Fatalf("cycle after a lifecycle change republished collections: %v", endpoint)
	}
}

// TestAIDiscoveryV8SignalsWithoutEndpointHookFailsOpen documents the degraded
// window between the observer being bound and the endpoint-inventory hook being
// bound. Only the endpoint hook can stamp the daily bundle clock, so a
// signals-only sequence keeps publishing the full snapshot. That is today's
// behavior — fail-open, never silent — and it self-corrects on the first cycle
// where both publishers run.
func TestAIDiscoveryV8SignalsWithoutEndpointHookFailsOpen(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)
	for attempt, scanID := range []string{"scan-1", "scan-2"} {
		capture := &endpointInventoryCapture{}
		adapter := &aiDiscoveryV8Adapter{runtime: capture, publishGate: gate}
		if err := adapter.EmitReport(t.Context(), managedGateReport(scanID, "alpha"), nil); err != nil {
			t.Fatal(err)
		}
		if counts := managedGateScanCounts(capture.snapshot()); counts["ai_component.observed"] != 1 {
			t.Fatalf("attempt %d: signals-only cycle went silent: %v", attempt, counts)
		}
	}
	// Once a full fanout runs, the bundle is stamped and steady state kicks in.
	managedGateFanout(t, gate, managedGateReport("scan-3", "alpha"))
	signals, endpoint := managedGateFanout(t, gate, managedGateReport("scan-4", "alpha"))
	if signals["ai_component.observed"] != 0 || len(endpoint) != 0 {
		t.Fatalf("full fanout did not settle: signals=%v endpoint=%v", signals, endpoint)
	}
}

// TestAIDiscoveryV8SignalsGateNeverDropsLifecycleDeltas: the counts term must
// keep new / changed / gone records — the exact records non-managed modes emit —
// publishable in every cycle, including one whose digest is unchanged.
func TestAIDiscoveryV8SignalsGateNeverDropsLifecycleDeltas(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)

	baseline := managedGateReport("scan-1", "alpha")
	baselineCapture := &endpointInventoryCapture{}
	baselineAdapter := &aiDiscoveryV8Adapter{runtime: baselineCapture, publishGate: gate}
	if err := baselineAdapter.EmitReport(t.Context(), baseline, nil); err != nil {
		t.Fatal(err)
	}

	// Same evidence set, but the scan reports a removal. `gone` signals are
	// excluded from the digest, so only the lifecycle-count term can save this.
	removal := managedGateReport("scan-2", "alpha")
	removal.Signals = append(removal.Signals, inventory.AISignal{
		SignalID: "ai-skill-beta", SignatureID: "skill", Category: inventory.SignalSkill,
		Vendor: "local", Product: "beta", Confidence: .9, State: inventory.AIStateGone,
		Detector: "skill_dir", EvidenceHash: "evidence-beta",
	})
	removal.Summary.GoneSignals = 1
	removalCapture := &endpointInventoryCapture{}
	removalAdapter := &aiDiscoveryV8Adapter{runtime: removalCapture, publishGate: gate}
	if err := removalAdapter.EmitReport(t.Context(), removal, nil); err != nil {
		t.Fatal(err)
	}
	if counts := managedGateScanCounts(removalCapture.snapshot()); counts["ai_component.removed"] != 1 {
		t.Fatalf("removal record was suppressed: %v", counts)
	}
}

// TestAIDiscoveryV8SignalsNonManagedUnchangedByGate is the OSS parity pin: the
// lifecycle-delta contract must hold across repeated identical reports, with no
// suppression and no state file.
func TestAIDiscoveryV8SignalsNonManagedUnchangedByGate(t *testing.T) {
	withManagedEnterprise(t, false)
	report := managedGateReport("scan-1", "alpha")
	report.Signals[0].State = inventory.AIStateNew
	report.Summary.NewSignals = 1
	report.Signals = append(report.Signals, inventory.AISignal{
		SignalID: "ai-skill-seen", SignatureID: "skill", Category: inventory.SignalSkill,
		Vendor: "local", Product: "seen", Confidence: .9, State: inventory.AIStateSeen,
		Detector: "skill_dir", EvidenceHash: "evidence-seen",
	})

	for attempt := range 2 {
		capture := &endpointInventoryCapture{}
		// Even with a gate bound, non-managed must be untouched.
		adapter := &aiDiscoveryV8Adapter{runtime: capture, publishGate: managedPublishTestState(t)}
		if err := adapter.EmitReport(t.Context(), report, nil); err != nil {
			t.Fatal(err)
		}
		counts := managedGateScanCounts(capture.snapshot())
		if counts["signals_summary"] != 1 {
			t.Fatalf("attempt %d: summary counts=%v", attempt, counts)
		}
		if counts["ai_component.discovered"] != 1 {
			t.Fatalf("attempt %d: non-managed delta was suppressed: %v", attempt, counts)
		}
		if counts["ai_component.observed"] != 0 {
			t.Fatalf("attempt %d: non-managed emitted a seen record: %v", attempt, counts)
		}
	}
}

// managedGateSourceCounts tallies emitted records by collection source, which is
// how a collection's presence or absence in a cycle is observed.
func managedGateSourceCounts(t *testing.T, records []observability.Record) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, record := range records {
		body := canonicalBody(t, record)
		source, _ := body[observability.TelemetryAttributeDefenseClawAIDiscoverySource].(string)
		counts[source]++
	}
	return counts
}

// TestAIDiscoveryV8SignalsGateManagedProjectionFailureStoresNoDigest is the
// per-signal half of the same rule.
func TestAIDiscoveryV8SignalsGateManagedProjectionFailureStoresNoDigest(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)

	// The per-signal records carry no ai.discovery.source attribute, so the fake
	// rejects every record except the liveness summary.
	rejected := &managedGateSignalRejectEmitter{}
	adapter := &aiDiscoveryV8Adapter{runtime: rejected, publishGate: gate}
	if err := adapter.EmitReport(t.Context(), managedGateReport("scan-1", "alpha"), nil); err != nil {
		t.Fatalf("managed projection failure must not surface as an emit error: %v", err)
	}
	if counts := managedGateScanCounts(rejected.snapshot()); counts["ai_component.observed"] == 0 {
		t.Fatalf("signals emitted nothing at all: %v", counts)
	}
	// Nothing was promised, so the cycle writes no state at all — the assertion is
	// that no signals digest exists, whether or not the file was created.
	if record, ok := managedPublishStoredRecord(t, gate, managedInventorySignalsKey); ok &&
		record.Digest != "" {
		t.Fatalf("signals digest stored despite a managed projection failure: %+v", record)
	}

	// Next scan with identical content still publishes the snapshot.
	replay := &endpointInventoryCapture{}
	next := &aiDiscoveryV8Adapter{runtime: replay, publishGate: gate}
	if err := next.EmitReport(t.Context(), managedGateReport("scan-2", "alpha"), nil); err != nil {
		t.Fatal(err)
	}
	if counts := managedGateScanCounts(replay.snapshot()); counts["ai_component.observed"] == 0 {
		t.Fatalf("signals snapshot suppressed after a managed projection failure: %v", counts)
	}
}

// managedGateSignalRejectEmitter reports a managed projection failure for every
// per-signal record while the liveness summary succeeds.
type managedGateSignalRejectEmitter struct {
	endpointInventoryCapture
}

func (emitter *managedGateSignalRejectEmitter) Emit(
	ctx context.Context,
	metadata router.Metadata,
	build observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	outcome, err := emitter.endpointInventoryCapture.Emit(ctx, metadata, build)
	if err == nil && emitter.lastRecord().EventName() != "ai.discovery.completed" {
		return pipeline.NewManagedOptionalFailureOutcomeForTest(
			pipeline.OptionalFailureProfile,
		), nil
	}
	return outcome, err
}
