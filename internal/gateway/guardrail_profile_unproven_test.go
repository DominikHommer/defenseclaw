// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of r104 W2B, loop 5. A lookup that fails only for want of a proof
// (SSSD stopped on a "passwd: files sss" host, NIS) selected default_profile
// through default_lookup_failed, weaker than the strict profile of the
// account's /etc/group membership. With the candidate facts of that lookup,
// a request whose candidate profile differs from the failed lookup's is
// refused (hooks fail closed); it is never moved to the weaker default, nor
// given a profile its account is not proved to have.

func unprovenProfileConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict":     {Mode: "action", BlockAt: "LOW"},
		"codex-only": {Mode: "action", BlockAt: "MEDIUM"},
		"uid-pinned": {Mode: "action", BlockAt: "HIGH"},
		"lenient":    {Mode: "observe"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "uid-pinned", Match: config.ProfileMatch{Users: []string{"1500"}}},
		{Profile: "codex-only", Match: config.ProfileMatch{Groups: []string{"codex-devs"}, Connectors: []string{"codex"}}},
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"strict-devs"}}},
	}
	cfg.Guardrail.DefaultProfile = "lenient"
	return cfg
}

const unprovenTestReason = "unixidentity: uid 1001: NSS service sss cannot show that it holds no other account of the uid"

// setUnprovenFacts makes entries the candidate facts of failed lookups.
func setUnprovenFacts(t *testing.T, entries map[string]unprovenFactsEntry) {
	t.Helper()
	unprovenFacts.Lock()
	prev := unprovenFacts.entries
	unprovenFacts.entries = entries
	unprovenFacts.Unlock()
	t.Cleanup(func() {
		unprovenFacts.Lock()
		unprovenFacts.entries = prev
		unprovenFacts.Unlock()
	})
}

func localCandidate(at time.Time, groups ...string) unprovenFactsEntry {
	return unprovenFactsEntry{facts: useridentity.DirectoryFacts{
		Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles,
		Assurance: useridentity.AssuranceVerified, ResolvedAt: at, Groups: groups,
	}, reason: unprovenTestReason, at: at}
}

func unprovenSubject(uid string) profileSubject {
	return profileSubject{UserID: uid, IDKind: useridentity.KindPOSIXUID, UserName: "opsadmin", LookupFailed: true}
}

func TestUnprovenLookupNeverFallsBackToAWeakerDefault(t *testing.T) {
	set, err := newGuardrailProfileSet(unprovenProfileConfig(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if set.matches == nil {
		t.Fatal("the profile set has no match cache; the cache case below would prove nothing")
	}
	now := time.Now()
	failed := unprovenSubject("1001")

	// Before any candidate: a lookup that failed another way keeps the
	// outage default (GAP-0312). The match cache now holds that decision.
	if got := set.match(&failed, profileSubjectVerified, "cursor", ""); got.Name != "lenient" || got.Refused != "" {
		t.Fatalf("failed lookup without a candidate = %+v; want lenient", got)
	}

	setUnprovenFacts(t, map[string]unprovenFactsEntry{
		"1001": localCandidate(now, "opsadmin", "strict-devs"),
		"1002": localCandidate(now, "opsbob"),
		"1003": localCandidate(now, "opscarol", "codex-devs"),
		"1500": localCandidate(now, "pinned", "strict-devs"),
		"1004": localCandidate(now.Add(-identityDirectoryTTL-time.Second), "olddev", "strict-devs"),
	})
	cases := []struct {
		name, uid, connector, kind string
		refused                    bool
		profile, match             string
	}{
		{name: "local group selects strict, the default is lenient", uid: "1001", connector: "cursor", refused: true, profile: "lenient"},
		{name: "same account through codex", uid: "1001", connector: "codex", refused: true, profile: "lenient"},
		{name: "no assignment applies to the candidate", uid: "1002", connector: "cursor", profile: "lenient"},
		{name: "group and connector assignment for its connector", uid: "1003", connector: "codex", refused: true, profile: "lenient"},
		{name: "group and connector assignment for another connector", uid: "1003", connector: "cursor", profile: "lenient"},
		{name: "assignment by uid needs no proof", uid: "1500", connector: "cursor", profile: "uid-pinned", match: profileMatchUser},
		{name: "candidate older than the facts lifetime", uid: "1004", connector: "cursor", profile: "lenient"},
		{name: "another uid's candidate", uid: "1005", connector: "cursor", profile: "lenient"},
		{name: "a SID never takes a uid candidate", uid: "1001", kind: useridentity.KindWindowsSID, connector: "cursor", profile: "lenient"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subject := unprovenSubject(tc.uid)
			if tc.kind != "" {
				subject.IDKind = tc.kind
			}
			if tc.match == "" {
				tc.match = profileMatchDefaultLookupFailed
			}
			got := set.match(&subject, profileSubjectVerified, tc.connector, "")
			if (got.Refused != "") != tc.refused || got.Name != tc.profile || got.Match != tc.match {
				t.Fatalf("decision = %+v; want refused=%t on %q (%s)", got, tc.refused, tc.profile, tc.match)
			}
			if tc.refused && !strings.Contains(got.Refused, "uid "+tc.uid) {
				t.Fatalf("refusal %q does not name the uid", got.Refused)
			}
		})
	}
	// A lookup that resolved is decided on its facts, whatever candidate an
	// earlier failure left.
	resolved := profileSubject{UserID: "1001", IDKind: useridentity.KindPOSIXUID, UserName: "opsadmin",
		Directory: useridentity.DirectoryLocal, Groups: []string{"opsadmin", "strict-devs"}, localAccount: true}
	if got := set.match(&resolved, profileSubjectVerified, "cursor", ""); got.Name != "strict" || got.Refused != "" {
		t.Fatalf("resolved facts = %+v; want strict", got)
	}
}

func TestUnprovenLookupRefusesTheHookAndInspectPaths(t *testing.T) {
	stubProfileSources(t)
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, unprovenProfileConfig())
	if api.guardrailProfileSet() == nil {
		t.Fatal("profiles were not derived at load")
	}
	setUnprovenFacts(t, map[string]unprovenFactsEntry{"1001": localCandidate(time.Now(), "opsadmin", "strict-devs")})
	verified := func(r *http.Request, uid string) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), testVerifiedSubjectKey{}, unprovenSubject(uid)))
	}
	hook := func(uid string) *httptest.ResponseRecorder {
		body := `{"hook_event_name":"tool.execute.before","tool_name":"read"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/opencode/hook", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		api.handleAgentHook("opencode").ServeHTTP(rec, verified(req, uid))
		return rec
	}
	rec := hook("1001")
	var refusal struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &refusal); rec.Code != http.StatusServiceUnavailable || err != nil ||
		!strings.Contains(refusal.Error, "cannot confirm which account uid 1001") {
		t.Fatalf("hook = %d %s; want 503 with the refusal", rec.Code, rec.Body.String())
	}
	if rec := hook("1002"); rec.Code != http.StatusOK {
		t.Fatalf("hook of a uid without a candidate = %d %s; want it decided", rec.Code, rec.Body.String())
	}

	reached := false
	inspect := api.guardrailProfileInspectMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec = httptest.NewRecorder()
	inspect.ServeHTTP(rec, verified(httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader("{}")), "1001"))
	if rec.Code != http.StatusServiceUnavailable || reached {
		t.Fatalf("inspect = %d (handler reached %t); want 503 before the handler", rec.Code, reached)
	}
	rec = httptest.NewRecorder()
	inspect.ServeHTTP(rec, verified(httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader("{}")), "1002"))
	if rec.Code != http.StatusOK || !reached {
		t.Fatalf("inspect of a uid without a candidate = %d (handler reached %t)", rec.Code, reached)
	}
}

func TestProfileExplainSaysWhyAnUnprovenAccountIsRefused(t *testing.T) {
	prevLookup := profileExplainSubjectLookup
	t.Cleanup(func() {
		profileExplainSubjectLookup = prevLookup
		liveGuardrailProfiles.Store(nil)
	})
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, unprovenProfileConfig())
	setUnprovenFacts(t, map[string]unprovenFactsEntry{"1001": localCandidate(time.Now(), "opsadmin", "strict-devs")})
	profileExplainSubjectLookup = func(string) (profileSubject, error) {
		subject := unprovenSubject("1001")
		subject.LookupError = unprovenTestReason
		return subject, nil
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?connector=codex&user=opsadmin", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	rec := httptest.NewRecorder()
	api.handleGuardrailProfileResolve(rec, req)
	var out struct {
		Profile  string   `json:"profile"`
		Match    string   `json:"match"`
		Refused  string   `json:"refused"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("explain: %v: %s", err, rec.Body.String())
	}
	note := strings.Join(out.Warnings, "\n")
	if out.Refused == "" || out.Match != profileMatchDefaultLookupFailed ||
		!strings.Contains(note, `selects profile "strict"`) || !strings.Contains(note, `a failed lookup selects profile "lenient"`) ||
		!strings.Contains(note, "cannot show that it holds no other account") {
		t.Fatalf("explain = %+v; want the refusal, both profiles and the reason", out)
	}
}

// The LLM proxy applies a verified caller's profile too: a refused request is
// answered 503 before it reaches the provider, not scanned with the proxy's
// own settings or the weaker default.
func TestUnprovenLookupRefusesTheLLMProxy(t *testing.T) {
	stubProfileSources(t)
	NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, unprovenProfileConfig())
	setUnprovenFacts(t, map[string]unprovenFactsEntry{"1001": localCandidate(time.Now(), "opsadmin", "strict-devs")})
	proxy := &GuardrailProxy{cfg: &config.GuardrailConfig{Connector: "openclaw"}, gatewayToken: "owner-token"}
	for _, path := range []string{"/v1/chat/completions", "/v1/messages"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"model":"m","messages":[]}`))
		req = req.WithContext(context.WithValue(req.Context(), testVerifiedSubjectKey{}, unprovenSubject("1001")))
		req.Header.Set("X-DC-Auth", "Bearer owner-token")
		rec := httptest.NewRecorder()
		if strings.HasSuffix(path, "/chat/completions") {
			proxy.handleChatCompletion(rec, req)
		} else {
			proxy.handlePassthrough(rec, req)
		}
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "cannot confirm which account uid 1001") {
			t.Fatalf("proxy %s = %d %s; want 503 with the refusal", path, rec.Code, rec.Body.String())
		}
	}
}

// Status and explain say how many accounts are refused for a missing proof.
func TestDirectoryHealthSaysUnprovenAccountsAreRefused(t *testing.T) {
	now := time.Now()
	setUnprovenFacts(t, map[string]unprovenFactsEntry{
		"1001": localCandidate(now, "opsadmin", "strict-devs"),
		"1004": localCandidate(now.Add(-identityDirectoryTTL-time.Second), "olddev"),
	})
	view, message := directoryHealthView(identityCacheHealth{Failing: 2, Since: now, LastError: unprovenTestReason}, now)
	if view["unproven"] != 1 || !strings.Contains(message, "for 1 account(s) only a proof is missing") ||
		!strings.Contains(message, "requests are refused") {
		t.Fatalf("health = %v, %q; want one unproven account whose requests are refused", view, message)
	}
	setUnprovenFacts(t, nil)
	if view, message := directoryHealthView(identityCacheHealth{Failing: 1, Since: now, LastError: "timeout"}, now); view["unproven"] != 0 ||
		strings.Contains(message, "refused") {
		t.Fatalf("health without unproven accounts = %v, %q", view, message)
	}
}
