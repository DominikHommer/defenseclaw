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
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// The managed sandbox counters are the fleet view of the managed sandbox
// records: defenseclaw.sandbox.managed.refusals, .asks, .foreign_items,
// .provisional and .drift. Each is a companion of its record and
// moves only when the record is admitted. Their labels are the guardrail
// profile name, the sandbox driver, the harness connector and one closed
// code; the host OS is the os.type resource attribute every record carries.
// No user, account, subject key, sandbox, registration, host or path is
// ever a label.

// Values of defenseclaw.metric.kind on defenseclaw.sandbox.managed.foreign_items.
const (
	SandboxForeignKindRule      = "rule"
	SandboxForeignKindSandbox   = "sandbox"
	SandboxForeignKindContainer = "container"
)

// Values of defenseclaw.metric.result on
// defenseclaw.sandbox.managed.provisional: a registration held
// to the offline floor while the directory lookup is pending (provisional),
// a provisional registration whose lookup has resolved (resolved), and
// either of them when the policy could not be built or applied (failed).
const (
	SandboxProvisionalOnFloor  = "provisional"
	SandboxProvisionalResolved = "resolved"
	SandboxProvisionalFailed   = "failed"
)

// sandboxManagedLabels are the labels every managed sandbox counter shares.
type sandboxManagedLabels struct {
	connector             string
	profile, driver, conn observability.Optional[string]
}

func sandboxManagedLabelsFor(identity SandboxIdentity, fields sandboxV8Fields) sandboxManagedLabels {
	return sandboxManagedLabels{
		connector: identity.Connector,
		profile:   fields.guardrailProfile,
		driver:    fields.driver,
		conn:      optionalSandboxEnum(identity.Connector),
	}
}

func sandboxManagedMetric(
	event Event,
	labels sandboxManagedLabels,
	instrument string,
	build func(*observability.FamilyBuilder, observability.FamilyEnvelopeInput) (observability.Record, error),
) RuntimeV8GeneratedMetric {
	event = sandboxMetricEvent(event, labels.connector)
	return RuntimeV8GeneratedMetric{
		family: observability.EventName(instrument),
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			envelope, err := sandboxMetricEnvelope(event, snapshot)
			if err != nil {
				return observability.Record{}, err
			}
			builder, err := sandboxMetricBuilder(event)
			if err != nil {
				return observability.Record{}, err
			}
			return build(builder, envelope)
		},
	}
}

func newSandboxManagedRefusalMetric(event Event, labels sandboxManagedLabels, reason observability.Optional[string]) []RuntimeV8GeneratedMetric {
	return []RuntimeV8GeneratedMetric{sandboxManagedMetric(event, labels, observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSandboxManagedRefusals(observability.MetricDefenseClawSandboxManagedRefusalsInput{
				Envelope: envelope, Value: 1, DefenseClawSandboxManagedReason: reason,
				DefenseClawGuardrailProfileName: labels.profile, DefenseClawSandboxDriver: labels.driver,
				DefenseClawConnectorSource: labels.conn,
			})
		})}
}

func newSandboxManagedAskMetric(event Event, labels sandboxManagedLabels, result string, reason observability.Optional[string]) []RuntimeV8GeneratedMetric {
	return []RuntimeV8GeneratedMetric{sandboxManagedMetric(event, labels, observability.TelemetryInstrumentDefenseClawSandboxManagedAsks,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSandboxManagedAsks(observability.MetricDefenseClawSandboxManagedAsksInput{
				Envelope: envelope, Value: 1, DefenseClawApprovalResult: observability.Present(result),
				DefenseClawSandboxManagedReason: reason,
				DefenseClawGuardrailProfileName: labels.profile, DefenseClawSandboxDriver: labels.driver,
				DefenseClawConnectorSource: labels.conn,
			})
		})}
}

func newSandboxManagedForeignMetric(event Event, labels sandboxManagedLabels, kind, action string) []RuntimeV8GeneratedMetric {
	return []RuntimeV8GeneratedMetric{sandboxManagedMetric(event, labels, observability.TelemetryInstrumentDefenseClawSandboxManagedForeignItems,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSandboxManagedForeignItems(observability.MetricDefenseClawSandboxManagedForeignItemsInput{
				Envelope: envelope, Value: 1, DefenseClawMetricKind: observability.Present(kind),
				DefenseClawSandboxManagedAction: observability.Present(action),
				DefenseClawGuardrailProfileName: labels.profile, DefenseClawSandboxDriver: labels.driver,
				DefenseClawConnectorSource: labels.conn,
			})
		})}
}

func newSandboxManagedProvisionalMetric(event Event, labels sandboxManagedLabels, result string) []RuntimeV8GeneratedMetric {
	return []RuntimeV8GeneratedMetric{sandboxManagedMetric(event, labels, observability.TelemetryInstrumentDefenseClawSandboxManagedProvisional,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSandboxManagedProvisional(observability.MetricDefenseClawSandboxManagedProvisionalInput{
				Envelope: envelope, Value: 1, DefenseClawMetricResult: observability.Present(result),
				DefenseClawGuardrailProfileName: labels.profile, DefenseClawSandboxDriver: labels.driver,
				DefenseClawConnectorSource: labels.conn,
			})
		})}
}

func newSandboxManagedDriftMetric(event Event, labels sandboxManagedLabels, field string) []RuntimeV8GeneratedMetric {
	return []RuntimeV8GeneratedMetric{sandboxManagedMetric(event, labels, observability.TelemetryInstrumentDefenseClawSandboxManagedDrift,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSandboxManagedDrift(observability.MetricDefenseClawSandboxManagedDriftInput{
				Envelope: envelope, Value: 1, DefenseClawOpenshellSettingsField: observability.Present(field),
				DefenseClawGuardrailProfileName: labels.profile, DefenseClawSandboxDriver: labels.driver,
				DefenseClawConnectorSource: labels.conn,
			})
		})}
}

// sandboxProvisionalResolution is the defenseclaw.sandbox.managed.provisional result of a
// policy resolution, "" when the registration was not provisional.
func sandboxProvisionalResolution(managed SandboxManaged, failed bool) string {
	if managed.Provisional == nil || !*managed.Provisional {
		return ""
	}
	if failed {
		return SandboxProvisionalFailed
	}
	return SandboxProvisionalOnFloor
}
