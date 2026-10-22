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
// moves only when the record is admitted. Their labels are the sandbox
// driver, the harness connector and one closed code; the host OS is the
// os.type resource attribute every record carries. No guardrail profile,
// directory group, user, account, subject key, sandbox, registration, host
// or path is ever a label: an operator may name a profile or a group after
// one person, so the profile view stays in the managed sandbox records.
//
// The reason and the setting key are labels only as values of the closed,
// code-defined sets below (sandboxManagedMetricReasons,
// sandboxManagedMetricSettingsFields). The daemon that reports a drift or an
// access refusal runs as the user, so the field or reason it posts is the
// user's claim: one the code does not define, such as a user name, counts as
// SandboxManagedMetricOther, and only the access-controlled record keeps it.

// SandboxManagedMetricOther is the counter value of a reason code or setting
// key that is not one of the code-defined values.
const SandboxManagedMetricOther = "other"

// sandboxManagedMetricReasons are the reason codes the managed gateway and
// daemon define for a refusal or an ask decision
// (defenseclaw.sandbox.managed.reason on .refusals and .asks).
var sandboxManagedMetricReasons = map[string]struct{}{
	// log.sandbox.host_run_refused
	"required_for": {},
	// log.sandbox.host_run_unavailable
	"os_unsupported": {}, "sandboxes_off": {}, "root_account": {}, "account_unverified": {},
	"no_docker": {}, "no_docker_access": {}, "no_docker_group": {}, "driver_unsupported": {},
	"no_kvm": {}, "no_kvm_access": {}, "no_kvm_group": {}, "prerequisite_missing": {}, "account_busy": {},
	// log.sandbox.access_refused
	"egress_proxy": {}, "egress_proposal": {}, "approved_rule_removed": {},
	// log.sandbox.ask.decided
	"floor_denied": {},
}

// sandboxManagedMetricSettingsFields are the OpenShell settings the daemon
// compares with enterprise.openshell, as it reports them
// (defenseclaw.openshell.settings.field on .drift).
var sandboxManagedMetricSettingsFields = map[string]struct{}{
	"compute_driver": {}, "gateway_listener": {}, "microvm_workload_identity": {},
	"docker_sandbox_namespace": {}, "openshell_telemetry": {},
	"gateway_configuration": {}, "gateway_command": {},
}

// SandboxManagedMetricReason is the counter value of a managed reason code:
// the code when the code defines it, otherwise SandboxManagedMetricOther.
func SandboxManagedMetricReason(code string) string {
	if _, ok := sandboxManagedMetricReasons[code]; ok {
		return code
	}
	return SandboxManagedMetricOther
}

// SandboxManagedMetricSettingsField is the counter value of a drifted
// OpenShell setting key: the key when the code defines it, otherwise
// SandboxManagedMetricOther.
func SandboxManagedMetricSettingsField(field string) string {
	if _, ok := sandboxManagedMetricSettingsFields[field]; ok {
		return field
	}
	return SandboxManagedMetricOther
}

func sandboxManagedMetricReason(reason observability.Optional[string]) observability.Optional[string] {
	code, ok := reason.Get()
	if !ok {
		return reason
	}
	return observability.Present(SandboxManagedMetricReason(code))
}

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
	connector    string
	driver, conn observability.Optional[string]
}

func sandboxManagedLabelsFor(identity SandboxIdentity, fields sandboxV8Fields) sandboxManagedLabels {
	return sandboxManagedLabels{
		connector: identity.Connector,
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
				Envelope: envelope, Value: 1, DefenseClawSandboxManagedReason: sandboxManagedMetricReason(reason),
				DefenseClawSandboxDriver:   labels.driver,
				DefenseClawConnectorSource: labels.conn,
			})
		})}
}

func newSandboxManagedAskMetric(event Event, labels sandboxManagedLabels, result string, reason observability.Optional[string]) []RuntimeV8GeneratedMetric {
	return []RuntimeV8GeneratedMetric{sandboxManagedMetric(event, labels, observability.TelemetryInstrumentDefenseClawSandboxManagedAsks,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSandboxManagedAsks(observability.MetricDefenseClawSandboxManagedAsksInput{
				Envelope: envelope, Value: 1, DefenseClawApprovalResult: observability.Present(result),
				DefenseClawSandboxManagedReason: sandboxManagedMetricReason(reason),
				DefenseClawSandboxDriver:        labels.driver,
				DefenseClawConnectorSource:      labels.conn,
			})
		})}
}

func newSandboxManagedForeignMetric(event Event, labels sandboxManagedLabels, kind, action string) []RuntimeV8GeneratedMetric {
	return []RuntimeV8GeneratedMetric{sandboxManagedMetric(event, labels, observability.TelemetryInstrumentDefenseClawSandboxManagedForeignItems,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSandboxManagedForeignItems(observability.MetricDefenseClawSandboxManagedForeignItemsInput{
				Envelope: envelope, Value: 1, DefenseClawMetricKind: observability.Present(kind),
				DefenseClawSandboxManagedAction: observability.Present(action),
				DefenseClawSandboxDriver:        labels.driver,
				DefenseClawConnectorSource:      labels.conn,
			})
		})}
}

func newSandboxManagedProvisionalMetric(event Event, labels sandboxManagedLabels, result string) []RuntimeV8GeneratedMetric {
	return []RuntimeV8GeneratedMetric{sandboxManagedMetric(event, labels, observability.TelemetryInstrumentDefenseClawSandboxManagedProvisional,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSandboxManagedProvisional(observability.MetricDefenseClawSandboxManagedProvisionalInput{
				Envelope: envelope, Value: 1, DefenseClawMetricResult: observability.Present(result),
				DefenseClawSandboxDriver:   labels.driver,
				DefenseClawConnectorSource: labels.conn,
			})
		})}
}

func newSandboxManagedDriftMetric(event Event, labels sandboxManagedLabels, field string) []RuntimeV8GeneratedMetric {
	return []RuntimeV8GeneratedMetric{sandboxManagedMetric(event, labels, observability.TelemetryInstrumentDefenseClawSandboxManagedDrift,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSandboxManagedDrift(observability.MetricDefenseClawSandboxManagedDriftInput{
				Envelope: envelope, Value: 1, DefenseClawOpenshellSettingsField: observability.Present(SandboxManagedMetricSettingsField(field)),
				DefenseClawSandboxDriver:   labels.driver,
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
