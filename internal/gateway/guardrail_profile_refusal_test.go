// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// refusalAlice is the verified account whose codex agent the tests resolve.
var refusalAlice = profileSubject{UserID: "70001", UserName: "alice"}

// refusalAgent stubs the request agent (alice's, as alice@corp.example), its
// 1.0.3 identity as the hook path derives it, and a ledger that cannot be
// read. It returns both identities.
func refusalAgent(t *testing.T) (agent, legacy string) {
	t.Helper()
	stubProfileSources(t)
	in := legacyBridgeInputs("alice@corp.example")
	agent, legacy = agentidentity.AgentID(in), agentidentity.LegacyAgentID(in)
	profileAgentSource = func(context.Context) (string, bool) { return agent, true }
	legacyBridgeDerives(t, in)
	refusalLedger(t, nil)
	return agent, legacy
}

// refusalLedger serves records as the agent ledger; nil cannot be read.
func refusalLedger(t *testing.T, records []inventory.AgentIdentityRecord) {
	t.Helper()
	previous := profileAgentLedger
	t.Cleanup(func() { profileAgentLedger = previous })
	profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) {
		return records, records != nil
	}
}

// refusalConfig assigns entry to the 1.0.3 agents entry legacy, then later
// ("" for none) to every codex agent; the default is def.
func refusalConfig(profiles map[string]config.GuardrailProfile, legacy, entry, later, def string) *config.Config {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = profiles
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: entry, Match: config.ProfileMatch{Agents: []string{legacy}}}}
	if later != "" {
		cfg.Guardrail.ProfileAssignments = append(cfg.Guardrail.ProfileAssignments,
			config.ProfileAssignment{Profile: later, Match: config.ProfileMatch{Connectors: []string{"codex"}}})
	}
	cfg.Guardrail.DefaultProfile = def
	return cfg
}

// The class: while the ledger cannot prove whose 1.0.3 agents entry it is,
// alice's codex agent gets a profile that enforces at least what every
// profile that may apply enforces, compared on everything a profile can
// enforce: hook and inspect mode, block level, rule pack and rules, HILT
// and sandbox section. Where none does, the decision is refused; before,
// two profiles that blocked alike were a tie and the default applied, so a
// default with a weaker rule pack or rules dropped the entry's rules.
func TestUnresolvedLegacyAgentProfilesThatDoNotCoverEachOtherAreRefused(t *testing.T) {
	packs := t.TempDir()
	strictDir, permissiveDir := filepath.Join(packs, "strict"), filepath.Join(packs, "permissive")
	disableEnvDump := &config.GuardrailRulesConfig{Disable: []string{"SEC-ENV-DUMP-REQUEST"}}
	sandbox := &config.OpenShellAdminConfig{EgressBlock: []string{"example.com"}}
	hilt := &config.HILTConfig{Enabled: true, MinSeverity: "medium"}
	for _, tc := range []struct {
		name              string
		entry, def, later config.GuardrailProfile
		withLater         bool
		wantName          string
		wantRefused       bool
	}{
		{name: "the entry's rule pack catches more", entry: config.GuardrailProfile{Mode: "action", BlockAt: "high", RulePackDir: strictDir},
			def: config.GuardrailProfile{Mode: "action", BlockAt: "high", RulePackDir: permissiveDir}, wantName: "default", wantRefused: true},
		{name: "the default's rule pack differs", entry: config.GuardrailProfile{Mode: "action", BlockAt: "high", RulePackDir: permissiveDir},
			def: config.GuardrailProfile{Mode: "action", BlockAt: "high", RulePackDir: strictDir}, wantName: "default", wantRefused: true},
		{name: "named rule packs differ", entry: config.GuardrailProfile{Mode: "action", BlockAt: "high", RulePack: "strict"},
			def: config.GuardrailProfile{Mode: "action", BlockAt: "high", RulePack: "permissive"}, wantName: "default", wantRefused: true},
		{name: "the default disables a rule", entry: config.GuardrailProfile{Mode: "action", BlockAt: "high"},
			def: config.GuardrailProfile{Mode: "action", BlockAt: "high", Rules: disableEnvDump}, wantName: "default", wantRefused: true},
		{name: "the entry's codex rule pack differs", entry: config.GuardrailProfile{Mode: "action", BlockAt: "low",
			Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {RulePackDir: strictDir}}},
			def: config.GuardrailProfile{Mode: "action", BlockAt: "high"}, wantName: "entry", wantRefused: true},
		{name: "a lower block level does not cover another sandbox section", entry: config.GuardrailProfile{Mode: "action", BlockAt: "low", Sandbox: sandbox},
			def: config.GuardrailProfile{Mode: "action", BlockAt: "high"}, wantName: "entry", wantRefused: true},
		{name: "a HILT that asks against a lower block level", entry: config.GuardrailProfile{Mode: "action", BlockAt: "critical", HILT: hilt},
			def: config.GuardrailProfile{Mode: "action", BlockAt: "high"}, wantName: "default", wantRefused: true},
		{name: "a later assignment's rule pack differs", entry: config.GuardrailProfile{Mode: "action", BlockAt: "high", RulePackDir: strictDir},
			later: config.GuardrailProfile{Mode: "action", BlockAt: "high", RulePackDir: permissiveDir}, withLater: true,
			def: config.GuardrailProfile{Mode: "observe"}, wantName: "entry", wantRefused: true},

		// Ordered: one profile covers every other.
		{name: "a lower block level with the same pack", entry: config.GuardrailProfile{Mode: "action", BlockAt: "low"},
			def: config.GuardrailProfile{Mode: "action", BlockAt: "critical"}, wantName: "entry"},
		{name: "a HILT that asks more", entry: config.GuardrailProfile{Mode: "action", BlockAt: "high", HILT: hilt},
			def: config.GuardrailProfile{Mode: "action", BlockAt: "high"}, wantName: "entry"},
		{name: "an observing default with another pack", entry: config.GuardrailProfile{Mode: "action", BlockAt: "high", RulePackDir: strictDir},
			def: config.GuardrailProfile{Mode: "observe", RulePackDir: permissiveDir}, wantName: "entry"},
		{name: "both observe", entry: config.GuardrailProfile{Mode: "observe", RulePackDir: strictDir},
			def: config.GuardrailProfile{Mode: "observe", RulePackDir: permissiveDir}, wantName: "default"},
		{name: "alert_at and block_message enforce nothing", entry: config.GuardrailProfile{Mode: "action", BlockAt: "high", AlertAt: "low", BlockMessage: "stop"},
			def: config.GuardrailProfile{Mode: "action", BlockAt: "high"}, wantName: "default"},
		{name: "another connector's rule pack", entry: config.GuardrailProfile{Mode: "action", BlockAt: "low",
			Connectors: map[string]config.PerConnectorGuardrailConfig{"claudecode": {RulePackDir: strictDir}}},
			def: config.GuardrailProfile{Mode: "action", BlockAt: "high"}, wantName: "entry"},
		{name: "the same sandbox section", entry: config.GuardrailProfile{Mode: "action", BlockAt: "low", Sandbox: sandbox},
			def: config.GuardrailProfile{Mode: "action", BlockAt: "high", Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{"example.com"}}}, wantName: "entry"},
		{name: "the default cannot apply", entry: config.GuardrailProfile{Mode: "action", BlockAt: "high", RulePackDir: strictDir},
			later: config.GuardrailProfile{Mode: "action", BlockAt: "high", RulePackDir: strictDir}, withLater: true,
			def: config.GuardrailProfile{Mode: "action", BlockAt: "high", RulePackDir: permissiveDir}, wantName: "entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, legacy := refusalAgent(t)
			profiles := map[string]config.GuardrailProfile{"entry": tc.entry, "default": tc.def}
			later := ""
			if tc.withLater {
				profiles["later"], later = tc.later, "later"
			}
			api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, refusalConfig(profiles, legacy, "entry", later, "default"))
			ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, refusalAlice)
			got := api.resolveProfile(api.withGuardrailProfileDecision(ctx, "codex"))
			if got.Name != tc.wantName || got.Refused != tc.wantRefused || got.Match != profileMatchDefaultLookupFailed {
				t.Errorf("decision %+v; want %s, refused %v, as default_lookup_failed", got, tc.wantName, tc.wantRefused)
			}
		})
	}
}

// Every profile field that can enforce is compared by profileCovers, or
// enforces nothing (description, alert_at, block_message), or is rejected
// in a profile (enabled, hook_fail_mode). A new field must be placed here.
func TestProfileCoversKnowsEveryProfileField(t *testing.T) {
	known := map[string]bool{
		"Description": true, "Mode": true, "BlockAt": true, "AlertAt": true, "HILT": true, "RulePackDir": true,
		"RulePack": true, "Rules": true, "BlockMessage": true, "Connectors": true, "Sandbox": true,
		"Enabled": true, "HookFailMode": true,
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(config.GuardrailProfile{}), reflect.TypeOf(config.PerConnectorGuardrailConfig{})} {
		for i := range typ.NumField() {
			if name := typ.Field(i).Name; !known[name] {
				t.Errorf("%s.%s: decide how profileCovers orders it", typ.Name(), name)
			}
		}
	}
}

// The reviewer's case end to end. strict and permissive block alike
// (action, block_at HIGH) with their own rule packs, and only strict's
// catches the marker. alice's 1.0.3 agents entry assigns strict, the
// default is permissive, and the ledger cannot be read. Before, the hook,
// the inspect endpoints, ACP and the proxy decided under permissive and the
// marker passed. Now each refuses the request, and explain says so. Once
// the ledger proves the entry is alice's, strict applies and its own rule
// blocks the marker, and nothing is refused.
func TestRefusedProfileDecisionIsRefusedOnEverySurface(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	priorManaged := ManagedEnterpriseActive()
	setManagedEnterpriseRedactionPosture(false)
	t.Cleanup(func() { setManagedEnterpriseRedactionPosture(priorManaged) })
	previous := liveGuardrailProfiles.Load()
	t.Cleanup(func() { liveGuardrailProfiles.Store(previous) })
	agent, legacy := refusalAgent(t)
	const marker = "refusal_strict_marker_token"
	root := t.TempDir()
	strictDir, permissiveDir := filepath.Join(root, "strict"), filepath.Join(root, "permissive")
	writeRulePackFixtureFile(t, strictDir, "rules/marker.yaml", `version: 1
category: secret
rules:
  - id: REFUSAL-STRICT-MARKER
    pattern: "`+marker+`"
    title: strict pack fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	writeRulePackFixtureFile(t, permissiveDir, "rules/other.yaml", `version: 1
category: secret
rules:
  - id: REFUSAL-PERMISSIVE-OTHER
    pattern: "refusal_unrelated_token"
    title: permissive pack fixture
    severity: HIGH
    confidence: 0.99
    tags: [test]
`)
	cfg := refusalConfig(map[string]config.GuardrailProfile{
		"strict":     {Mode: "action", BlockAt: "high", RulePackDir: strictDir},
		"permissive": {Mode: "action", BlockAt: "high", RulePackDir: permissiveDir},
	}, legacy, "strict", "", "permissive")
	cfg.Guardrail.Mode = "action"
	cfg.ACP = config.ACPConfig{
		Enabled: true, Mode: "action", DefaultProfile: "default",
		Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "default"}},
		Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "default"}},
		Profiles: map[string]config.ACPProfile{"default": {
			Mode: "action", AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
		}},
	}
	subject := func(ctx context.Context) context.Context {
		return context.WithValue(ctx, testVerifiedSubjectKey{}, refusalAlice)
	}
	refused := func(reason string) bool { return strings.Contains(reason, "cannot be matched to this account") }

	hook := func(api *APIServer, command string) (action, reason string) {
		t.Helper()
		body := `{"hook_event_name":"tool.execute.before","tool_name":"bash","tool_input":{"command":"` + command + `"}}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/opencode/hook", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(subject(req.Context()))
		rec := httptest.NewRecorder()
		api.handleAgentHook("opencode").ServeHTTP(rec, req)
		var resp struct {
			Action string `json:"action"`
			Reason string `json:"reason"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
			t.Fatalf("hook status=%d body=%s", rec.Code, rec.Body.String())
		}
		return resp.Action, resp.Reason
	}
	inspect := func(api *APIServer, path string, handler http.HandlerFunc, body string, middleware bool) ToolInspectVerdict {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req = req.WithContext(withAuthenticatedInspectConnector(subject(req.Context()), "codex"))
		rec := httptest.NewRecorder()
		var h http.Handler = handler
		if middleware {
			h = api.guardrailProfileInspectMiddleware(handler)
		}
		h.ServeHTTP(rec, req)
		var verdict ToolInspectVerdict
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &verdict) != nil {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		return verdict
	}

	t.Run("the ledger cannot be read", func(t *testing.T) {
		api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
		if action, reason := hook(api, "cat "+marker); action != "block" || !refused(reason) {
			t.Errorf("hook: action %q, reason %q; want the refusal", action, reason)
		}
		for _, check := range []struct {
			path    string
			handler http.HandlerFunc
			body    string
		}{
			{"/api/v1/inspect/tool", api.handleInspectTool, `{"tool":"bash","args":{"command":"cat ` + marker + `"}}`},
			{"/api/v1/inspect/request", api.handleInspectRequest, `{"content":"` + marker + `"}`},
			{"/api/v1/inspect/response", api.handleInspectResponse, `{"content":"` + marker + `"}`},
			{"/api/v1/inspect/tool-response", api.handleInspectToolResponse, `{"tool":"bash","output":"` + marker + `"}`},
		} {
			// Through the inspect middleware, and straight to the handler
			// as a sandbox relay calls it.
			for _, middleware := range []bool{true, false} {
				if verdict := inspect(api, check.path, check.handler, check.body, middleware); verdict.Action != "block" || !refused(verdict.Reason) {
					t.Errorf("%s (middleware %v): verdict %+v; want the refusal", check.path, middleware, verdict)
				}
			}
		}

		frame := `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"s","prompt":[{"type":"text","text":"` + marker + `"}]}}`
		body, err := json.Marshal(acp.Evaluation{
			Profile: "default", Mode: acp.ModeAction, AgentID: "kiro", ClientID: "zed",
			Direction: acp.ClientToAgent, Surface: acp.SurfacePrompt, Method: "session/prompt", Payload: json.RawMessage(frame),
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body))
		api.handleACPEvaluate(rec, req.WithContext(subject(req.Context())))
		var verdict acp.Verdict
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &verdict) != nil || verdict.Action != "block" || !refused(verdict.Reason) {
			t.Errorf("ACP: status %d body %s; want the refusal", rec.Code, rec.Body.String())
		}

		proxy := &GuardrailProxy{cfg: &config.GuardrailConfig{Connector: "codex"}, gatewayToken: "owner-token"}
		req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
			strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"`+marker+`"}]}`))
		req.Header.Set("X-DC-Auth", "Bearer owner-token")
		rec = httptest.NewRecorder()
		proxy.handleChatCompletion(rec, req.WithContext(subject(req.Context())))
		if rec.Code != http.StatusForbidden || !refused(rec.Body.String()) {
			t.Errorf("proxy: status %d body %s; want 403 with the refusal", rec.Code, rec.Body.String())
		}

		req = httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?user=not-a-real-account&connector=codex&agent="+agent, nil)
		req.RemoteAddr = "127.0.0.1:40000"
		rec = httptest.NewRecorder()
		api.handleGuardrailProfileResolve(rec, req)
		var explained map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &explained) != nil || explained["refused"] != true {
			t.Errorf("explain: status %d body %s; want refused", rec.Code, rec.Body.String())
		}
	})

	t.Run("the ledger proves the entry", func(t *testing.T) {
		refusalLedger(t, []inventory.AgentIdentityRecord{legacyBridgeRecord(legacy, "alice@corp.example")})
		api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
		if action, reason := hook(api, "ls"); action == "block" || refused(reason) {
			t.Errorf("hook: action %q, reason %q; want it decided under strict, not refused", action, reason)
		}
		if verdict := inspect(api, "/api/v1/inspect/request", api.handleInspectRequest, `{"content":"`+marker+`"}`, true); verdict.Action != "block" || refused(verdict.Reason) {
			t.Errorf("inspect: verdict %+v; want the strict pack's block", verdict)
		}
	})
}
