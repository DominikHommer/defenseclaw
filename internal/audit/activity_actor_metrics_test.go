// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestActivityMetricsKeepAccountActorsOnlyInAudit(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	actor := "cli:sample-account"
	if err := logger.LogActivity(ActivityInput{Actor: actor, Action: ActionConfigUpdate, TargetType: "config"}); err != nil {
		t.Fatal(err)
	}
	if err := logger.LogPolicyBundleReceipt("operator:sample-account", PolicyBundle{ID: testPolicyBundleID, Version: 5},
		PolicyBundleReceipt{ReceiptID: testPolicyBundleID, Actor: actor, State: PolicyBundleConfirmed}); err != nil {
		t.Fatal(err)
	}
	if err := logger.LogConfigChange(ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeSecret,
		Action: "set", Outcome: ConfigChangeApplied, Actor: actor, SecretName: "sample-credential"}); err != nil {
		t.Fatal(err)
	}
	rows, err := logger.store.ListEvents(10)
	if err != nil || len(rows) != 3 {
		t.Fatalf("audit rows=%d: %v", len(rows), err)
	}
	for _, row := range rows {
		if row.Actor != actor {
			t.Errorf("audit actor=%q, want %q", row.Actor, actor)
		}
	}
	var activityMetrics int
	for _, metric := range runtime.metricSnapshot() {
		switch metric.EventName() {
		case observability.EventName(observability.TelemetryInstrumentDefenseClawActivityTotal),
			observability.EventName(observability.TelemetryInstrumentDefenseClawActivityDiffEntries):
			activityMetrics++
			if got := generatedMetricAttributes(t, metric)["defenseclaw.metric.actor"]; got != "local_account" {
				t.Errorf("metric actor=%v, want fixed category local_account", got)
			}
		}
	}
	if activityMetrics != 6 {
		t.Fatalf("activity metrics=%d, want 6", activityMetrics)
	}
}
