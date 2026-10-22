// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Review of r104 W2B, loop round 2. A uid two accounts hold (two
// /etc/passwd names, a local and a directory account) has no candidate that
// tells which account a request is from. Its failed lookup selected the
// lenient default, where the first local account's strict group profile
// applied before. Such a request is now refused whenever an assignment the
// request could match selects another profile than the failed lookup's.
func TestASharedUIDIsRefusedWhenAnotherProfileCouldApply(t *testing.T) {
	set, err := newGuardrailProfileSet(unprovenProfileConfig(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	const reason = "unixidentity: uid 1001 is held by more than one account (opsadmin (files), opsclone (files))"
	ambiguous := unprovenFactsEntry{reason: reason, at: now, ambiguous: true}

	// The match cache holds the decision taken before the ambiguity was
	// known; it must not be served after.
	failed := unprovenSubject("1001")
	if got := set.match(&failed, profileSubjectVerified, "cursor", ""); got.Refused != "" || got.Name != "lenient" {
		t.Fatalf("before the ambiguity = %+v; want the outage default", got)
	}
	setUnprovenFacts(t, map[string]unprovenFactsEntry{"1001": ambiguous, "1500": ambiguous,
		"1004": {reason: reason, at: now.Add(-identityDirectoryTTL - time.Second), ambiguous: true}})
	for _, tc := range []struct {
		name, uid, connector string
		refused              bool
		profile, match       string
	}{
		{name: "a group assignment could select strict", uid: "1001", connector: "cursor", refused: true, profile: "lenient"},
		{name: "a group and connector assignment for its connector", uid: "1001", connector: "codex", refused: true, profile: "lenient"},
		{name: "an assignment by the uid needs no account", uid: "1500", connector: "cursor", profile: "uid-pinned", match: profileMatchUser},
		{name: "an ambiguity older than the facts lifetime", uid: "1004", connector: "cursor", profile: "lenient"},
		{name: "another uid", uid: "1002", connector: "cursor", profile: "lenient"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.match == "" {
				tc.match = profileMatchDefaultLookupFailed
			}
			subject := unprovenSubject(tc.uid)
			got := set.match(&subject, profileSubjectVerified, tc.connector, "")
			if (got.Refused != "") != tc.refused || got.Name != tc.profile || got.Match != tc.match {
				t.Fatalf("decision = %+v; want refused=%t on %q (%s)", got, tc.refused, tc.profile, tc.match)
			}
			if tc.refused && !strings.Contains(got.Refused, "more than one account holds the uid") {
				t.Fatalf("refusal %q does not say why", got.Refused)
			}
		})
	}

	// Only assignments the request cannot match: no refusal.
	cfg := unprovenProfileConfig()
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"strict-devs"}, Connectors: []string{"codex"}}},
		{Profile: "strict", Match: config.ProfileMatch{Users: []string{"1700", "1701"}}},
		{Profile: "lenient", Match: config.ProfileMatch{Groups: []string{"lenient-devs"}}},
	}
	narrow, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	subject := unprovenSubject("1001")
	if got := narrow.match(&subject, profileSubjectVerified, "cursor", ""); got.Refused != "" || got.Name != "lenient" {
		t.Fatalf("no assignment for this request selects another profile: %+v; want the default", got)
	}
	// A users entry that is a name could be either account.
	cfg.Guardrail.ProfileAssignments = append(cfg.Guardrail.ProfileAssignments,
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{"1700", "opsclone"}}})
	byName, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := byName.match(&subject, profileSubjectVerified, "cursor", ""); got.Refused == "" {
		t.Fatalf("a users entry by name could select strict: %+v; want refused", got)
	}

	// Explain says why.
	note := unprovenRefusalNote(set, &subject, set.match(&subject, profileSubjectVerified, "cursor", ""), "cursor", "")
	if !strings.Contains(note, "more than one account holds its uid") || !strings.Contains(note, "opsclone (files)") {
		t.Fatalf("explain note = %q; want the shared uid and its accounts", note)
	}
}

// The hook and inspect paths answer 503 for a shared uid an assignment
// could decide, so hooks fail closed.
func TestASharedUIDIsRefusedOnTheHookAndInspectPaths(t *testing.T) {
	stubProfileSources(t)
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, unprovenProfileConfig())
	if api.guardrailProfileSet() == nil {
		t.Fatal("profiles were not derived at load")
	}
	setUnprovenFacts(t, map[string]unprovenFactsEntry{"1001": {reason: "uid 1001 is shared", at: time.Now(), ambiguous: true}})
	verified := func(r *http.Request, uid string) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), testVerifiedSubjectKey{}, unprovenSubject(uid)))
	}
	for _, uid := range []string{"1001", "1002"} {
		body := `{"hook_event_name":"tool.execute.before","tool_name":"read"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/opencode/hook", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		api.handleAgentHook("opencode").ServeHTTP(rec, verified(req, uid))
		if uid == "1001" && (rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "more than one account holds the uid")) {
			t.Fatalf("hook of the shared uid = %d %s; want 503 with the refusal", rec.Code, rec.Body.String())
		}
		if uid == "1002" && rec.Code != http.StatusOK {
			t.Fatalf("hook of another uid = %d %s; want it decided", rec.Code, rec.Body.String())
		}
	}
	reached := false
	inspect := api.guardrailProfileInspectMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	inspect.ServeHTTP(rec, verified(httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader("{}")), "1001"))
	if rec.Code != http.StatusServiceUnavailable || reached {
		t.Fatalf("inspect = %d (handler reached %t); want 503 before the handler", rec.Code, reached)
	}
}
