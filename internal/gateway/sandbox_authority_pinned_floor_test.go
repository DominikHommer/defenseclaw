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

package gateway

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// pinnedFloorProfiles makes contractors the strict profile (github.com
// blocked, no unblock) and engineering the loose one, with contractors
// assigned to dc-sbx-contractors and engineering to dc-sbx-devs, or both
// groups to one profile (to).
func pinnedFloorProfiles(f *sandboxFixture, to string) {
	no := false
	f.cfg.Guardrail.Profiles["contractors"] = config.GuardrailProfile{Description: "Contractors",
		Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{"github.com"}, AllowUnblock: &no}}
	f.cfg.Guardrail.Profiles["engineering"] = config.GuardrailProfile{Description: "Engineering"}
	contractors, devs := "contractors", "engineering"
	if to != "" {
		contractors, devs = to, to
	}
	f.cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: contractors, Match: config.ProfileMatch{Groups: []string{"dc-sbx-contractors"}}},
		{Profile: devs, Match: config.ProfileMatch{Groups: []string{"dc-sbx-devs"}}},
	}
	f.publishFirstGeneration()
}

// GAP-0242: floors are pinned at create per sandbox. A profile-assignment
// change re-matches a running sandbox to the new profile but runs it under
// the stricter of the two floors: a sandbox created under the strict
// profile keeps github.com blocked after its group moved to the loose one,
// and one created under the loose profile is tightened when its group moved
// to the strict one. The person's next sandbox takes the new profile alone.
func TestSandboxAuthorityAssignmentChangeOnlyTightensARunningSandbox(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.setGroups(sbxBob, "dc-sbx-devs")
	pinnedFloorProfiles(f, "")
	strict := f.live(sbxAlice, 1)
	loose := f.live(sbxBob, 2)
	if strict.Banner.Profile != "contractors" || loose.Banner.Profile != "engineering" {
		t.Fatalf("banners: %+v %+v", strict.Banner, loose.Banner)
	}
	blocked := func(g *sandboxFixture, peer managedHookPeer, id string) (string, bool) {
		t.Helper()
		code, cur := g.current(peer, id)
		if code != http.StatusOK || cur.Revoked {
			t.Fatalf("policy/current: %d %+v", code, cur)
		}
		return cur.Profile, slices.Contains(cur.Live.EgressBlock, "github.com") && cur.Live.AllowUnblock != nil && !*cur.Live.AllowUnblock
	}
	if _, ok := blocked(f, sbxAlice, strict.Registration.ID); !ok {
		t.Fatal("the strict sandbox does not block github.com before the change")
	}
	if _, ok := blocked(f, sbxBob, loose.Registration.ID); ok {
		t.Fatal("the loose sandbox blocks github.com before the change")
	}

	// Both groups move to the loose profile: the strict sandbox stays strict.
	toLoose := newSandboxFixtureOn(t, f)
	pinnedFloorProfiles(toLoose, "engineering")
	if profile, ok := blocked(toLoose, sbxAlice, strict.Registration.ID); profile != "engineering" || !ok {
		t.Fatalf("after the move to engineering the strict-created sandbox is profile %q, still strict %v", profile, ok)
	}
	auth, _ := toLoose.api.sandboxAuth()
	if reg, _, _ := auth.store.Get(sbxAlice.UID, strict.Registration.ID); reg.CreateProfile == nil || *reg.CreateProfile != "contractors" {
		t.Fatalf("the create profile moved: %+v", reg.CreateProfile)
	}
	// A new sandbox of the same person takes the loose profile alone.
	fresh := toLoose.live(sbxAlice, 3)
	if profile, ok := blocked(toLoose, sbxAlice, fresh.Registration.ID); profile != "engineering" || ok {
		t.Fatalf("a sandbox created after the move: profile %q, strict %v", profile, ok)
	}

	// Both groups move to the strict profile: the loose sandbox is tightened.
	toStrict := newSandboxFixtureOn(t, toLoose)
	pinnedFloorProfiles(toStrict, "contractors")
	if profile, ok := blocked(toStrict, sbxBob, loose.Registration.ID); profile != "contractors" || !ok {
		t.Fatalf("after the move to contractors the loose-created sandbox is profile %q, strict %v", profile, ok)
	}
	// And back: the sandbox created loose is loose again, the strict one strict.
	back := newSandboxFixtureOn(t, toStrict)
	pinnedFloorProfiles(back, "")
	if _, ok := blocked(back, sbxBob, loose.Registration.ID); ok {
		t.Fatal("the loose-created sandbox stayed tightened after its own profile came back")
	}
	if _, ok := blocked(back, sbxAlice, strict.Registration.ID); !ok {
		t.Fatal("the strict-created sandbox lost its floor")
	}
}

// A registration from before floors were pinned at create (no
// create_profile in the store file) takes the profile it was last matched
// under as its minimum at its first re-match.
func TestSandboxAuthorityPinsTheFloorOfAnEarlierRegistration(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	pinnedFloorProfiles(f, "")
	resp := f.live(sbxAlice, 1)

	path := filepath.Join(f.cfg.DataDir, "sandbox", "registrations", strconv.Itoa(sbxAlice.UID)+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	regs, _ := doc["registrations"].([]any)
	if len(regs) != 1 {
		t.Fatalf("registrations: %v", doc["registrations"])
	}
	reg := regs[0].(map[string]any)
	if reg["create_profile"] != "contractors" {
		t.Fatalf("create_profile = %v", reg["create_profile"])
	}
	delete(reg, "create_profile")
	if raw, err = json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	moved := newSandboxFixtureOn(t, f)
	pinnedFloorProfiles(moved, "engineering")
	code, cur := moved.current(sbxAlice, resp.Registration.ID)
	if code != http.StatusOK || cur.Profile != "engineering" || !slices.Contains(cur.Live.EgressBlock, "github.com") {
		t.Fatalf("an earlier registration after the move: %d %+v", code, cur)
	}
}
