// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of r104 W2B, loop round 3. A directory account (no /etc/passwd
// entry) in strict-devs, on a host where a service before SSSD on the
// passwd line did not answer for its uid: the lookup failed with no
// candidate, and the request got the lenient default. The lookup is now
// unproven: with the candidate the SSSD account gives, or with none when
// the candidate pass fails too. Without a candidate the request is refused
// whenever an assignment could select another profile than the failed
// lookup's, and explain says why.
func TestAnUnprovenOwnerNeverFallsBackToAWeakerDefault(t *testing.T) {
	setUnprovenFacts(t, nil)
	set, err := newGuardrailProfileSet(unprovenProfileConfig(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	prevLocal, prevNSS := peerLocalCandidate, peerNSSFacts
	t.Cleanup(func() { peerLocalCandidate, peerNSSFacts = prevLocal, prevNSS })
	peerLocalCandidate = func(int, time.Time) (string, useridentity.DirectoryFacts, bool, error) {
		return "", useridentity.DirectoryFacts{}, false, nil
	}
	ownerErr := errors.New("unixidentity: NSS service nis did not answer whether it holds uid 41401: getent timed out: " +
		"the directory did not show that it answers")
	end := func(key string, err error) {
		t.Helper()
		peerNSSFacts = func(string) (useridentity.DirectoryFacts, error) {
			if err != nil {
				return useridentity.DirectoryFacts{}, err
			}
			return useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Assurance: useridentity.AssuranceVerified,
				ResolvedAt: time.Now(), Groups: []string{"carol", "strict-devs"}}, nil
		}
		_, _ = resolvePeerDirectoryFacts(key)
	}
	subject := func(uid string) *profileSubject {
		s := unprovenSubject(uid)
		s.UserName = "carol"
		return &s
	}
	refused := func(t *testing.T, got profileDecision, why string) {
		t.Helper()
		if got.Refused == "" || !strings.Contains(got.Refused, why) || got.Name != "lenient" || got.Match != profileMatchDefaultLookupFailed {
			t.Fatalf("decision = %+v; want a refusal that says %q", got, why)
		}
	}
	notRefused := func(t *testing.T, got profileDecision, profile string) {
		t.Helper()
		if got.Refused != "" || got.Name != profile {
			t.Fatalf("decision = %+v; want %q, not refused", got, profile)
		}
	}

	// The SSSD account's candidate selects strict: refused.
	end("41401", &unixidentity.UnprovenFactsError{Err: ownerErr, Candidate: useridentity.DirectoryFacts{
		Source: useridentity.SourceSSSD, Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(), Groups: []string{"carol", "strict-devs"}}})
	refused(t, set.match(subject("41401"), profileSubjectVerified, "cursor", ""), "uid 41401")

	// No candidate: refused for every connector an identity assignment
	// could still select another profile for.
	end("41401", &unixidentity.UnprovenFactsError{Err: ownerErr})
	for _, connector := range []string{"cursor", "codex"} {
		refused(t, set.match(subject("41401"), profileSubjectVerified, connector, ""), "did not answer")
	}
	got := set.match(subject("41401"), profileSubjectVerified, "cursor", "")
	if note := unprovenRefusalNote(set, subject("41401"), got, "cursor", ""); !strings.Contains(note, "could not tell which account") ||
		!strings.Contains(note, "nis did not answer") {
		t.Fatalf("explain note = %q; want why the account is refused", note)
	}

	// An assignment by the uid needs no account: it applies.
	end("1500", &unixidentity.UnprovenFactsError{Err: ownerErr})
	notRefused(t, set.match(subject("1500"), profileSubjectVerified, "cursor", ""), "uid-pinned")

	// Assignments only by other uids cannot select another profile.
	cfg := unprovenProfileConfig()
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Users: []string{"1500"}}}}
	byUID, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	notRefused(t, byUID.match(subject("41401"), profileSubjectVerified, "cursor", ""), "lenient")

	// A plain failure keeps the outage default (GAP-0312, unchanged).
	end("41402", errors.New("sssd: no reply"))
	notRefused(t, set.match(subject("41402"), profileSubjectVerified, "cursor", ""), "lenient")

	// A lookup that resolves drops the unknown account.
	end("41401", nil)
	notRefused(t, set.match(subject("41401"), profileSubjectVerified, "cursor", ""), "lenient")

	// The hook answers 503 (hooks fail closed); the base answered 200 in the
	// lenient profile's observe mode.
	stubProfileSources(t)
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, unprovenProfileConfig())
	if api.guardrailProfileSet() == nil {
		t.Fatal("profiles were not derived at load")
	}
	end("41401", &unixidentity.UnprovenFactsError{Err: ownerErr})
	body := `{"hook_event_name":"tool.execute.before","tool_name":"read"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/opencode/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), testVerifiedSubjectKey{}, *subject("41401")))
	rec := httptest.NewRecorder()
	api.handleAgentHook("opencode").ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "did not answer") {
		t.Fatalf("hook of the unknown account = %d %s; want 503 with the refusal", rec.Code, rec.Body.String())
	}
}
