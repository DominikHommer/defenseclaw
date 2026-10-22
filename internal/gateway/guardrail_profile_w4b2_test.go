// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestW4B2UnconfirmedGroupRefusesInsteadOfLenientDefault(t *testing.T) {
	set := &guardrailProfileSet{
		defaultProfile: "watch",
		profiles: map[string]config.DerivedGuardrailProfile{
			"watch": {}, "strict": {}, "user": {},
		},
		assignments: []config.ProfileAssignment{
			{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"ldap-privileged"}}},
		},
	}
	for _, subject := range []profileSubject{
		{UserID: "1001", Groups: []string{"local-only"}, GroupsUnknown: true},
		{UserID: "1001", LookupFailed: true},
	} {
		decision := set.matchUncached(&subject, profileSubjectVerified, "codex", "")
		if !decision.RefuseUnconfirmedGroups || decision.Match != profileMatchDefaultLookupFailed {
			t.Fatalf("unconfirmed LDAP membership selected %+v; want a refusal", decision)
		}
	}
	set.assignments[0].Match.Users = []string{"2002"}
	other := profileSubject{UserID: "1001", GroupsUnknown: true}
	if decision := set.matchUncached(&other, profileSubjectVerified, "codex", ""); decision.RefuseUnconfirmedGroups {
		t.Fatalf("an assignment for a proved different UID caused refusal: %+v", decision)
	}
	set.assignments = append([]config.ProfileAssignment{{Profile: "user", Match: config.ProfileMatch{Users: []string{"1001"}}}}, set.assignments...)
	if decision := set.matchUncached(&other, profileSubjectVerified, "codex", ""); decision.RefuseUnconfirmedGroups || decision.Name != "user" {
		t.Fatalf("an earlier verified UID assignment lost precedence: %+v", decision)
	}
}

func TestW4B2HookBlocksUnconfirmedGroupMembership(t *testing.T) {
	stubProfileSources(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"watch": {Mode: "observe"}, "strict": {Mode: "action"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"ldap-privileged"}}},
	}
	cfg.Guardrail.DefaultProfile = "watch"
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "1001", GroupsUnknown: true})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook",
		strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"true"}}`)).WithContext(ctx)
	rec := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(rec, req)
	var verdict agentHookResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &verdict); err != nil || rec.Code != http.StatusOK || verdict.Action != "block" ||
		!strings.Contains(verdict.Reason, "defenseclaw guardrail profile explain --user 1001") {
		t.Fatalf("hook status=%d verdict=%+v decode=%v; want a fail-closed refusal", rec.Code, verdict, err)
	}
}

func TestW4B2ProxyAndInspectRefuseUnconfirmedGroupMembership(t *testing.T) {
	stubProfileSources(t)
	previous := liveGuardrailProfiles.Load()
	t.Cleanup(func() { liveGuardrailProfiles.Store(previous) })
	cfg := &config.Config{}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"watch": {Mode: "observe"}, "strict": {Mode: "action"},
	}
	cfg.Guardrail.DefaultProfile = "watch"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"ldap-privileged"}}},
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	subject := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "1001", GroupsUnknown: true})
	proxy := &GuardrailProxy{cfg: &config.GuardrailConfig{Connector: "openclaw"}, gatewayToken: "owner-token"}
	for _, path := range []string{"/v1/chat/completions", "/v1/messages"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"model":"fixture","messages":[]}`)).WithContext(subject)
		req.Header.Set("X-DC-Auth", "Bearer owner-token")
		rec := httptest.NewRecorder()
		if path == "/v1/chat/completions" {
			proxy.handleChatCompletion(rec, req)
		} else {
			proxy.handlePassthrough(rec, req)
		}
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "directory group membership is unconfirmed") {
			t.Fatalf("proxy %s: status=%d body=%q; want refused before forwarding", path, rec.Code, rec.Body.String())
		}
	}
	called := false
	handler := api.guardrailProfileInspectMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/guardrail/evaluate", nil).WithContext(subject))
	if called || rec.Code != http.StatusForbidden {
		t.Fatalf("inspect called=%t status=%d; want refusal", called, rec.Code)
	}
}

func TestW4B2ACPRefusesUnconfirmedGroupMembership(t *testing.T) {
	stubProfileSources(t)
	cfg := &config.Config{ACP: config.ACPConfig{
		Enabled: true, Mode: "observe", DefaultProfile: "default",
		Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "default"}},
		Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "default"}},
		Profiles: map[string]config.ACPProfile{"default": {
			Mode: "observe", AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
		}},
	}}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"watch": {Mode: "observe"}, "strict": {Mode: "action"},
	}
	cfg.Guardrail.DefaultProfile = "watch"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"ldap-privileged"}}},
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	payload := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"terminal/create","params":{"sessionId":"s","command":"true","args":[]}}`)
	body, err := json.Marshal(acp.Evaluation{
		Profile: "default", Mode: acp.ModeObserve, AgentID: "kiro", ClientID: "zed",
		Direction: acp.AgentToClient, Surface: acp.SurfaceTerminal, Method: "terminal/create", Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, profileSubject{UserID: "1001", GroupsUnknown: true})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	api.handleACPEvaluate(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "directory group membership is unconfirmed") {
		t.Fatalf("ACP status=%d body=%q; want refused even in observe mode", rec.Code, rec.Body.String())
	}
}
