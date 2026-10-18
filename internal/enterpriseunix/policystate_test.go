// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// policyDigestRunner answers the installed gateway's `policy digest --json`;
// an empty digest makes it fail, as it does when a pack no longer matches its pin.
type policyDigestRunner struct {
	*fakeRunner
	digest string
}

func (r *policyDigestRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if strings.Join(args, " ") == "policy digest --json" {
		if r.digest == "" {
			return CommandResult{Stderr: []byte("policy digest: pack digest mismatch"), ExitCode: 1}, nil
		}
		return CommandResult{Stdout: []byte(`{"effective_digest":"` + r.digest + `","config_generation":4}`)}, nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

// servePolicyHealth makes a running gateway answer /health with the policy
// digest and last reload error the pointers hold at the time of the probe.
func servePolicyHealth(h *testHost, reported, reloadError *string) {
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		if !h.healthy || !h.services.isActive(unitGateway) {
			return 0, nil, errors.New("connection refused")
		}
		return 200, []byte(`{"api":{"state":"running"},"policy":{"effective_digest":"` + *reported + `","last_reload_error":"` + *reloadError + `"},"inspection":{"local":"active","ai_defense":"disabled"}}`), nil
	}
}

// TestEnsureReportsTheAppliedPolicy covers the result's policy object: the
// digest the installed config computes to, whether the gateway reports the
// same one, policy-state.json once it does, and a warning when it does not.
// deployment.json still loads with a field this release does not know, so a
// later release can extend it.
func TestEnsureReportsTheAppliedPolicy(t *testing.T) {
	const computed = "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
	h := newTestHost(t, "linux")
	h.env.Runner = &policyDigestRunner{fakeRunner: h.runner, digest: computed}
	reported, reloadError := computed, ""
	servePolicyHealth(h, &reported, &reloadError)
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	requireOK(t, r)
	if r.Policy == nil || !r.Policy.Applied || r.Policy.EffectiveDigest != computed || r.Policy.ConfigGeneration != 4 {
		t.Fatalf("install policy = %+v, want %s applied at config generation 4", r.Policy, computed)
	}
	if record, err := h.env.loadPolicyState(); err != nil || record == nil || record.EffectiveDigest != computed {
		t.Fatalf("policy-state.json = %+v, %v", record, err)
	}

	reported = "sha256:" + strings.Repeat("0", 64)
	r = h.run(Options{Action: ActionRepair})
	if r.Policy == nil || r.Policy.Applied || r.Policy.GatewayReportedDigest != reported || !hasWarning(r, codePolicyNotApplied) {
		t.Fatalf("repair with a stale gateway: policy = %+v, warnings = %+v", r.Policy, r.Warnings)
	}

	// A reload the gateway rejected leaves the digests equal, but the policy
	// is not applied, and status says so without a change action (GAP-0044).
	reported, reloadError = computed, "pack digest mismatch"
	r = h.run(Options{Action: ActionStatus})
	if r.Policy == nil || r.Policy.Applied || r.Policy.LastReloadError != reloadError || !hasWarning(r, codePolicyReloadRejected) {
		t.Fatalf("status with a rejected reload: policy = %+v, warnings = %+v", r.Policy, r.Warnings)
	}
	// GAP-0587: a change action does not add "reports X but computes to X".
	if r = h.run(Options{Action: ActionRepair}); hasWarning(r, codePolicyNotApplied) || !hasWarning(r, codePolicyReloadRejected) {
		t.Fatalf("repair with a rejected reload: warnings = %+v", r.Warnings)
	}

	raw, err := os.ReadFile(h.env.deploymentPath())
	if err != nil {
		t.Fatal(err)
	}
	extended := strings.Replace(string(raw), "{", `{"added_by_a_later_release": true,`, 1)
	if err := os.WriteFile(h.env.deploymentPath(), []byte(extended), 0o600); err != nil {
		t.Fatal(err)
	}
	if record, err := h.env.loadDeployment(); err != nil || record == nil {
		t.Fatalf("loadDeployment with an unknown field = %v, %v", record, err)
	}
}

// TestPolicyOmittedWhenTheDigestIsUnknown covers a gateway that reports a
// digest while the installed config's policy cannot be built (a pack that no
// longer matches its pin) and no policy-state.json records an earlier one:
// the result has no policy object, because the lifecycle-result schema
// requires effective_digest to be a sha256 digest, and the gateway's
// rejected reload is still warned about.
func TestPolicyOmittedWhenTheDigestIsUnknown(t *testing.T) {
	const computed = "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
	h := newTestHost(t, "linux")
	runner := &policyDigestRunner{fakeRunner: h.runner, digest: computed}
	h.env.Runner = runner
	reported, reloadError := computed, ""
	servePolicyHealth(h, &reported, &reloadError)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))

	if err := os.Remove(h.env.policyStatePath()); err != nil {
		t.Fatal(err)
	}
	runner.digest, reloadError = "", "pack digest mismatch"
	r := h.run(Options{Action: ActionStatus})
	if r.Policy != nil {
		t.Fatalf("status with no computable digest: policy = %+v, want none", r.Policy)
	}
	if !hasWarning(r, codePolicyReloadRejected) {
		t.Fatalf("the rejected reload is not warned about: %+v", r.Warnings)
	}
	if raw, err := json.Marshal(r); err != nil || strings.Contains(string(raw), `"effective_digest"`) {
		t.Fatalf("result JSON = %s, %v; it must not carry an effective_digest", raw, err)
	}
}

// GAP-0133: a sandbox pack under the policies directory edited in place
// leaves config.yaml and every installed file as applied, but the config now
// computes to another effective policy than the running gateway reports.
// ensure is no noop then: it records the next config_generation and starts
// the gateway again, which loads the edit; the following ensure is a noop
// with the policy applied. A gateway that rejected its last reload is not
// restarted again for the same difference.
func TestEnsureAppliesAPolicyAssetEditedInPlace(t *testing.T) {
	before := "sha256:" + strings.Repeat("ab12", 16)
	after := "sha256:" + strings.Repeat("cd34", 16)
	h := newTestHost(t, "linux")
	runner := &policyDigestRunner{fakeRunner: h.runner, digest: before}
	h.env.Runner = runner
	reported, reloadError := before, ""
	servePolicyHealth(h, &reported, &reloadError)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	generation := func() uint64 {
		t.Helper()
		state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
		if err != nil {
			t.Fatal(err)
		}
		return state.Generation
	}
	gatewayStarts := func(from int) int {
		h.services.mu.Lock()
		defer h.services.mu.Unlock()
		n := 0
		for _, call := range h.services.calls[from:] {
			if call == "start "+unitGateway || call == "restart "+unitGateway {
				n++
			}
		}
		return n
	}
	r := h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	if !r.Noop || r.NoopReason != "up_to_date" {
		t.Fatalf("ensure with nothing changed: noop %v (%s)", r.Noop, r.NoopReason)
	}
	first := generation()

	runner.digest = after
	h.services.mu.Lock()
	mark := len(h.services.calls)
	h.services.mu.Unlock()
	r = h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	if r.Noop {
		t.Fatalf("ensure after the pack edit was a noop (%s); warnings %+v", r.NoopReason, r.Warnings)
	}
	if got := generation(); got != first+1 {
		t.Fatalf("config_generation = %d, want %d", got, first+1)
	}
	if gatewayStarts(mark) == 0 {
		t.Fatal("the gateway was not started again to load the edited pack")
	}

	// The gateway now runs the edited pack.
	reported = after
	r = h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	if !r.Noop || r.Policy == nil || !r.Policy.Applied || r.Policy.EffectiveDigest != after {
		t.Fatalf("ensure after the gateway loaded the edit: noop %v policy %+v", r.Noop, r.Policy)
	}

	// A reload the gateway rejected is reported, not restarted for again.
	runner.digest, reloadError = before, "pack digest mismatch"
	if r = h.run(Options{Action: ActionEnsure}); !r.Noop || !hasWarning(r, codePolicyReloadRejected) {
		t.Fatalf("ensure with a rejected reload: noop %v warnings %+v", r.Noop, r.Warnings)
	}
}
