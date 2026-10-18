// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0151: an enrolled managed Hermes whose version has no verified hook
// contract has no DefenseClaw hook, so status and verify report the
// deployment as not covering it (coverage_complete false) and name the agent
// with hook_contract_unverified. A target the guardian failed for another
// reason keeps its own warning and leaves coverage as it was.
func TestAgentWithoutAHookContractIsNotCovered(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	writeState := func(results ...map[string]any) {
		t.Helper()
		if results == nil {
			results = []map[string]any{}
		}
		state, _ := json.Marshal(map[string]any{"results": results})
		if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), state, 0o640); err != nil {
			t.Fatal(err)
		}
	}

	writeState(map[string]any{"user": "carol", "connector": "omnigent", "ok": false,
		"error": "enterprise hooks: connector omnigent setup failed: interpreter is not in a trusted install prefix"})
	if baseline := h.run(Options{Action: ActionStatus}); !baseline.CoverageComplete {
		t.Fatalf("baseline status is not coverage complete: readiness=%+v", baseline.Readiness)
	}

	writeState(
		map[string]any{"user": "dcr-std1", "connector": "hermes", "ok": true},
		map[string]any{"user": "eng1@dclab.test", "connector": "hermes", "ok": false,
			"error": `enterprise hooks: connector hermes agent version "2026.9.24" is not verified against a known hook contract: no hook contract matches normalized agent version`},
	)
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if r.CoverageComplete || r.SecurityComplete {
			t.Fatalf("%s: coverage_complete=%t security_complete=%t with an agent that has no hook", action, r.CoverageComplete, r.SecurityComplete)
		}
		if msg := messagesOf(r.Warnings, codeHookContractUnverified); !strings.Contains(msg, "hermes 2026.9.24 for user eng1@dclab.test") ||
			!strings.Contains(msg, "runs without DefenseClaw hooks") {
			t.Fatalf("%s: hook_contract_unverified warning = %q", action, msg)
		}
	}

	// The enumerator's unprotected-agents record says the same for an agent
	// it could not enroll because its version has no hook contract.
	writeState()
	data, err := enterprisehooks.MarshalUnprotectedAgents([]enterprisehooks.UnprotectedAgent{{
		User:      "eng1@dclab.test",
		Connector: "hermes",
		Version:   "2026.9.24",
		Code:      enterprisehooks.UnprotectedCodeHookContractUnverified,
		Reason:    "version 2026.9.24 is not verified against a known hook contract; it runs without DefenseClaw hooks",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionStatus})
	if r.CoverageComplete || messagesOf(r.Warnings, enterprisehooks.UnprotectedCodeHookContractUnverified) == "" {
		t.Fatalf("unprotected-agents record: coverage_complete=%t warnings=%+v", r.CoverageComplete, r.Warnings)
	}
}
