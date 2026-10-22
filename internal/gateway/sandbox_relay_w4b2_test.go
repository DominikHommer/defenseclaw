//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func TestW4B2SandboxRelayRefusesUnconfirmedGroups(t *testing.T) {
	previousFacts, previousBlocking := identityFactsEnabled.Load(), identityLookupBlocking.Load()
	previousDirectory, previousRematch := managedHookPeerDirectory, sandboxRecordRematched
	identityFactsEnabled.Store(true)
	identityLookupBlocking.Store(true)
	managedHookPeerDirectory = func(int, bool) (useridentity.DirectoryFacts, bool) {
		return useridentity.DirectoryFacts{}, false
	}
	sandboxRecordRematched = func(*APIServer, sandboxreg.Registration, sandboxreg.Registration, []string, string) {}
	t.Cleanup(func() {
		identityFactsEnabled.Store(previousFacts)
		identityLookupBlocking.Store(previousBlocking)
		managedHookPeerDirectory, sandboxRecordRematched = previousDirectory, previousRematch
	})

	const path = sandboxrelay.PathInspectPrefix + "tool"
	called := false
	f := newRelayFixtureWith(t, map[string]sandboxRelayRoute{path: {
		class: sandboxauth.RouteInspect, native: "/api/v1/inspect/tool",
		handler: func(http.ResponseWriter, *http.Request) { called = true },
	}}, func(c *config.Config) {
		c.Guardrail.Profiles = map[string]config.GuardrailProfile{
			"watch": {Mode: "observe"}, "strict": {Mode: "action"},
		}
		c.Guardrail.DefaultProfile = "watch"
		c.Guardrail.ProfileAssignments = []config.ProfileAssignment{
			{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"ldap-privileged"}}},
		}
	})
	reg := f.register(t, "unconfirmed-groups", "claudecode", relayTestBindingID(0xb21))
	resp, body := f.post(t, path, reg.ID, `{}`)
	if called || resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "directory group membership is unconfirmed") {
		t.Fatalf("relay handler called=%t, status=%d body=%q; want fail-closed refusal", called, resp.StatusCode, body)
	}
}
