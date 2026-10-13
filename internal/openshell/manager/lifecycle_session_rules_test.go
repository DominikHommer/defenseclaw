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

//go:build !windows

package manager

import (
	"errors"
	"strings"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A managed start whose two tries to remove the rule approved for the last
// session both fail (before the start and once the sandbox runs) does not
// leave the new session running with that rule: the start stops the
// sandbox again and names the rule; the next start removes it
// (rel-1-0-2:GAP-0014, LF-LEAD P2-2).
func TestManagedStartStopsWhenTheLastSessionRuleCannotBeRemoved(t *testing.T) {
	e, _ := managedEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	e.live(sandboxapi.CreateRequest{Name: "srfail"})
	e.register("srfail")
	host := "session.example.org"
	e.propose("srfail", host)
	e.draft("srfail")
	asks := e.waitAsks("srfail", 1)
	must(t, e.decide(asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve"}))
	rule := ruleFor(host)
	eventually(t, "the approved rule "+rule, func() bool {
		return e.approvedRules("srfail")[rule] == actorOperator && e.hasRule("srfail", rule)
	})
	e.waitAsks("srfail", 0)
	e.stopBox("srfail")

	busy := &types.StatusError{Code: types.ErrorUnavailable, Message: "policy store busy"}
	before := e.fake.Calls(openshelltest.MethodUpdateConfig)
	e.fake.FailNext(openshelltest.MethodUpdateConfig, busy)
	e.fake.FailNext(openshelltest.MethodUpdateConfig, busy)
	_, err := e.m.Start(t.Context(), "srfail", sandboxapi.StartRequest{})
	if got := e.fake.Calls(openshelltest.MethodUpdateConfig) - before; got != 2 {
		t.Fatalf("policy updates during the start = %d, want the two removal tries", got)
	}
	var apiErr *sandboxapi.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("start with the last session's rule still in the policy = %v, want a refusal", err)
	}
	if !strings.Contains(apiErr.Message, rule) || !strings.Contains(apiErr.Message, "stopped it again") {
		t.Fatalf("refusal = %q, want it to name %s and say the sandbox was stopped", apiErr.Message, rule)
	}
	if strings.Contains(err.Error(), "policy store busy") {
		t.Fatalf("refusal shows the gateway's raw error: %q", err.Error())
	}
	if phase := e.get("srfail").Phase; phase != "stopped" {
		t.Fatalf("sandbox phase after the refused start = %q, want stopped", phase)
	}
	if e.approvedRules("srfail")[rule] != actorOperator {
		t.Fatal("the record forgot the rule that is still in the policy")
	}

	e.startBox("srfail", sandboxapi.StartRequest{})
	if e.hasRule("srfail", rule) {
		t.Fatal("the next start kept the last session's rule")
	}
}
