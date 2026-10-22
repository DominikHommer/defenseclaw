// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Privacy (decision 4 of the 1.0.4 identity design). A caller whose facts
// are unproven gets the strictest combination of the profiles that may
// apply, and one of them may be another account's (an assignment that may
// name the caller while its facts are unproven). Settings, policy/explain,
// policy/test and policy/packs must not show that profile: its name, its
// description or its egress policy. The combination is enforced; a live
// registration takes it through a re-match, and stays live.
func TestSandboxPolicyViewsOfAnUnprovenDecisionNameNoOtherProfile(t *testing.T) {
	const secret = "bob-internal.example"
	setup := func(t *testing.T) *sandboxFixture {
		t.Helper()
		f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
		f.cfg.Guardrail.Profiles["bob-only"] = config.GuardrailProfile{Description: "Bob private profile", Mode: "action",
			Sandbox: &config.OpenShellAdminConfig{EgressAllowOnly: []string{secret}}}
		f.cfg.Guardrail.ProfileAssignments = append([]config.ProfileAssignment{
			{Profile: "bob-only", Match: config.ProfileMatch{Users: []string{sbxBob.Name}}},
			{Profile: "bob-only", Match: config.ProfileMatch{Groups: []string{"dc-sbx-bob-team"}}},
		}, f.cfg.Guardrail.ProfileAssignments...)
		f.publishFirstGeneration()
		return f
	}
	groupsUnknown := func(f *sandboxFixture, peer managedHookPeer) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.facts[peer.UID] = useridentity.DirectoryFacts{
			Principal: peer.Name + "@DCLAB.TEST", Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
			Source: "sssd", GroupsPartial: true, ResolvedAt: time.Now(),
		}
	}
	leaks := func(body string) bool {
		return strings.Contains(body, "bob-only") || strings.Contains(body, "Bob private") || strings.Contains(body, secret)
	}
	views := func(t *testing.T, f *sandboxFixture, header map[string]string, registration string) {
		t.Helper()
		for _, call := range []struct {
			name, method, path string
			body               any
		}{
			{"settings", http.MethodGet, sandboxrelay.PathSettings, nil},
			{"explain", http.MethodPost, sandboxrelay.PathPolicyExplain, sandboxrelay.ExplainRequest{V: 1, Connector: "claudecode", Registration: registration}},
			{"test", http.MethodPost, sandboxrelay.PathPolicyTest, sandboxrelay.PolicyTestRequest{V: 1, Checks: []sandboxapi.PolicyCheck{{Host: "pkg.example", Port: 443}}}},
			{"packs", http.MethodGet, sandboxrelay.PathPolicyPacks, nil},
		} {
			rec := f.do(sbxAlice, call.method, call.path, call.body, header)
			if rec.Code != http.StatusOK {
				t.Errorf("%s: %d %s; want the view (no refusal)", call.name, rec.Code, rec.Body.String())
			}
			if leaks(rec.Body.String()) {
				t.Errorf("%s: %d %s names another account's profile", call.name, rec.Code, rec.Body.String())
			}
		}
	}
	t.Run("account lookup failed", func(t *testing.T) {
		f := setup(t)
		// explain, test and packs wait identityDirectoryBudget for the lookup.
		f.coldCache(sbxAlice)
		views(t, f, map[string]string{sandboxrelay.ConnectorHeader: "claudecode"}, "")
	})
	t.Run("groups unknown", func(t *testing.T) {
		f := setup(t)
		groupsUnknown(f, sbxAlice)
		views(t, f, map[string]string{sandboxrelay.ConnectorHeader: "claudecode"}, "")
	})
	t.Run("a live registration re-matched while its facts are unproven", func(t *testing.T) {
		f := setup(t)
		f.setGroups(sbxAlice, "dc-sbx-contractors")
		resp := f.live(sbxAlice, 1)
		if resp.Registration.Provisional || resp.Banner.Profile != "contractors" {
			t.Fatalf("create: %+v %+v", resp.Registration, resp.Banner)
		}
		groupsUnknown(f, sbxAlice)
		views(t, f, map[string]string{sandboxrelay.ConnectorHeader: "claudecode", sandboxrelay.RegistrationHeader: resp.Registration.ID}, resp.Registration.ID)
		auth, _ := f.api.sandboxAuth()
		reg, ok, err := auth.store.Get(sbxAlice.UID, resp.Registration.ID)
		members, _ := config.ProfileMeetMembers(reg.Profile)
		if err != nil || !ok || (reg.Profile != "contractors" && !slices.Contains(members, "contractors")) || reg.State != sandboxreg.StateLive {
			t.Errorf("registration after the unproven re-match: %+v (%v); want contractors or a combination with it, live", reg, err)
		}
	})
}
