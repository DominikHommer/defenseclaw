// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// #1199 (GAP-0607, GAP-0561, rel GAP-0168): after a regroup the gateway
// re-matched the registration, and `policy explain` named the new profile,
// but `sandbox status NAME` named no organization profile at all and the
// refusals named the old one. The views of a sandbox now carry the profile
// and digest of the registration's current match, and the refusals' profile
// lookup gives the same profile.
func TestSandboxViewsNameTheRematchedProfile(t *testing.T) {
	c := newClosedFloorFixture(t)
	ctx := context.Background()
	if err := c.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Profile: "engineering", Digest: "sha256:old",
		Floor: closedFloorRegFloor, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	c.sandboxDaemonFixture.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:contractors", Profile: "contractors"}, nil
	}
	c.d.pollOnce(ctx)
	for _, v := range c.statusAndList(t, "dc-a") {
		if v.OrganizationProfile != "contractors" || v.PolicyDigest != "sha256:contractors" || v.StopReason != "" {
			t.Fatalf("after the regroup: profile %q digest %q stop %q", v.OrganizationProfile, v.PolicyDigest, v.StopReason)
		}
	}
	if profile, ok := c.d.decisionsClient().SandboxProfile("dc-a"); !ok || profile != "contractors" {
		t.Fatalf("the refusals' profile = %q, %v", profile, ok)
	}
}

// #1199 (GAP-0560, rel GAP-0417): a stop a re-match asked for (the profile
// no longer allows host ports) ended the session with "stopped from outside
// this session" and the activity feed with a 403 hook line. The daemon keeps
// the managed gateway's words for the revoke, the sandbox's views give them,
// and the feed says them when the daemon stops the sandbox.
func TestRematchStopKeepsTheOrganizationsWords(t *testing.T) {
	c := newClosedFloorFixture(t)
	ctx := context.Background()
	stop := sandboxapi.ProfileStop("host ports", "codex", "it-help@example.com")
	c.sandboxDaemonFixture.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Revoked: true, RevokedReason: stop}, nil
	}
	revoked := c.d.pollRegistrations(ctx, false)
	if len(revoked) != 1 || revoked[0].StopText != stop {
		t.Fatalf("revoked = %+v", revoked)
	}
	if r, _ := c.d.regs.get("dc-a"); !r.Revoked || r.StopText != stop {
		t.Fatalf("registration = %+v", r)
	}
	for _, v := range c.statusAndList(t, "dc-a") {
		if v.StopReason != stop || v.OrganizationProfile != "" {
			t.Fatalf("after the stop: stop %q profile %q", v.StopReason, v.OrganizationProfile)
		}
	}
	c.d.notePolicyStop(revoked[0])
	events := c.d.rt.manager.ActivitySince(0, "dc-a")
	if !slices.ContainsFunc(events, func(e sandboxapi.ActivityEvent) bool {
		return e.Reason == sandboxPolicyStopReason && e.Message == stop
	}) {
		t.Fatalf("activity = %+v", events)
	}

	// A refusal that ended the registration (404, 410, 409) carries a
	// reason code, not words: the views add nothing then.
	g := newClosedFloorFixture(t)
	g.sandboxDaemonFixture.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{}, &sandboxrelay.Error{Status: 410, Reason: "revoked"}
	}
	g.d.pollOnce(ctx)
	if r, _ := g.d.regs.get("dc-a"); !r.Revoked || r.StopText != "" {
		t.Fatalf("registration after a 410 = %+v", r)
	}
	for _, v := range g.statusAndList(t, "dc-a") {
		if v.StopReason != "" {
			t.Fatalf("a reason code shown as the stop: %q", v.StopReason)
		}
	}
}

// #1199 (GAP-0600): after a daemon restart the stopped sandbox's list entry
// lost its required pack and read strict (pack balanced), the closed
// start-up floor's resolution. While the managed gateway does not answer the
// list says the policy is being confirmed; once it answers, the entry has
// the required pack the registration carries and its network profile.
func TestColdStoppedSandboxKeepsItsRequiredPack(t *testing.T) {
	packDir := t.TempDir()
	file := filepath.Join(packDir, "contractors-b10", packs.PackFileName)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("version: 1\nname: contractors-b10\nextends: balanced\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.OpenShell.Admin.RequiredPack = file
	eff, _, err := packs.Resolve(cfg, packs.Flags{})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(eff)
	if err != nil {
		t.Fatal(err)
	}
	var carried struct {
		Pack *packs.Pack `json:"pack"`
	}
	if err := json.Unmarshal(wire, &carried); err != nil || carried.Pack == nil {
		t.Fatalf("pack wire form: %v", err)
	}
	// The account cannot read the administrator's pack folder.
	if err := os.RemoveAll(filepath.Dir(file)); err != nil {
		t.Fatal(err)
	}
	floor := config.OpenShellAdminConfig{RequiredPack: file, RequestAccess: "it-help@example.com"}

	var answers atomic.Bool
	created := map[string]any{"pack": "contractors-b10", "profile": "balanced", "network_mode": "allowlist", "approvals": "triage"}
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		seedSandboxRecord(t, o.StateDir, "dc-a", created)
		o.listPhases = func(context.Context) (map[string]string, bool) { return map[string]string{"dc-a": "stopped"}, true }
		// The registrations file the daemon left before its restart.
		doc := map[string]any{"v": 1, "registrations": []daemonRegistration{{ID: "reg-1", Sandbox: "dc-a", Profile: "contractors",
			Digest: "sha256:contractors", Floor: floor, RequiredPack: carried.Pack, UpdatedAt: time.Now().UTC()}}}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(o.StateDir, sandboxDaemonRegistrationsFile), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		if !answers.Load() {
			return sandboxrelay.CurrentPolicy{}, errors.New("connect: connection refused")
		}
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:contractors", Profile: "contractors"}, nil
	}
	runPastRevalidate(t, f)
	f.d.rt.manager.RefreshPolicies()
	ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
	ctx := context.Background()
	list, err := ctl.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if v := list[0]; !slices.Contains(v.Warnings, sandboxConfirmingNote) || v.Pack != "contractors-b10" || v.Profile != "balanced" {
		t.Fatalf("while confirming: pack %q profile %q warnings %q", v.Pack, v.Profile, v.Warnings)
	}
	answers.Store(true)
	list, err = ctl.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if v := list[0]; v.Pack != "contractors-b10" || v.Profile != "balanced" || v.NetworkMode == "deny" ||
		slices.Contains(v.Warnings, sandboxConfirmingNote) || v.OrganizationProfile != "contractors" {
		t.Fatalf("after the confirmation: pack %q profile %q/%s org %q warnings %q", v.Pack, v.Profile, v.NetworkMode,
			v.OrganizationProfile, v.Warnings)
	}
}
