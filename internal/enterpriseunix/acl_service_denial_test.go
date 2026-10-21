// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// p0.GAP-1442: on macOS a rule pack whose ACL denies the gateway service
// account a read, a listing or a pass-through is refused before anything
// changes, though its owner and mode bits let the account read it. Entries
// for other accounts, and entries that only pass to new children, do not
// count.
func TestDarwinRulePackReadDeniedByACLIsRefused(t *testing.T) {
	h := newTestHost(t, "darwin")
	if _, err := h.env.Accounts.Ensure(context.Background(), h.env.Layout.ServiceUser); err != nil {
		t.Fatal(err)
	}
	const dir = "/Library/DefenseClaw-packs/custom"
	file := filepath.Join(dir, "rules.yaml")
	if err := os.MkdirAll(h.env.P(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(file), []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	service := "user:" + h.env.Layout.ServiceUser
	for _, tc := range []struct {
		path, entry string
		refused     bool
	}{
		{file, service + " deny read", true},
		{dir, "group:everyone deny list", true},
		{filepath.Dir(dir), service + " inherited deny search", true},
		{file, "user:alice deny read", false},
		{file, service + " deny read,file_inherit,only_inherit", false},
		{file, service + " allow read", false},
	} {
		h.runner.acls = map[string][]string{h.env.P(tc.path): {tc.entry}}
		got := h.env.RulePackServiceReadProblem(context.Background(), dir)
		if tc.refused != (got != "") || (tc.refused && (!strings.Contains(got, tc.entry) || !strings.Contains(got, tc.path))) {
			t.Fatalf("%q on %s: problem = %q, refused want %v", tc.entry, tc.path, got, tc.refused)
		}
	}
	// Linux has no macOS ACLs: an entry the fake ls would print is never read.
	linux := newTestHost(t, "linux")
	if _, err := linux.env.Accounts.Ensure(context.Background(), linux.env.Layout.ServiceUser); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linux.env.P(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	linux.runner.acls = map[string][]string{linux.env.P(dir): {"group:everyone deny list"}}
	if got := linux.env.RulePackServiceReadProblem(context.Background(), dir); got != "" {
		t.Fatalf("Linux read a macOS ACL: %q", got)
	}
}

// p0.GAP-1414: on macOS a new JSONL output file below a folder whose ACL
// denies the gateway service account creating entries, or passing through,
// is refused before anything changes, though the folder's owner and mode
// let the account write it.
func TestDarwinJSONLParentDeniedByACLIsRefused(t *testing.T) {
	for _, tc := range []struct{ entry, want string }{
		{"deny add_file", "denies it"},
		{"deny search", "from passing through"},
	} {
		h := newTestHost(t, "darwin")
		account, err := h.accounts.Ensure(t.Context(), h.env.Layout.ServiceUser)
		if err != nil {
			t.Fatal(err)
		}
		parent := filepath.Join(h.env.Layout.LogDir, "gateway", "exports")
		if err := os.MkdirAll(h.env.P(filepath.Dir(parent)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(h.env.P(parent), 0o700); err != nil {
			t.Fatal(err)
		}
		h.owners[h.env.P(parent)] = [2]int{account.UID, account.GID}
		h.runner.acls = map[string][]string{h.env.P(parent): {"user:" + h.env.Layout.ServiceUser + " " + tc.entry}}
		path := filepath.Join(parent, "events.jsonl")
		raw := string(DefaultConfig(h.env.Layout)) + "observability:\n  destinations:\n    - name: events\n      kind: jsonl\n      path: " + path + "\n"
		if got := installMessage(t, h, raw); !strings.Contains(got, `destination "events" writes `+path) ||
			!strings.Contains(got, tc.want) || !strings.Contains(got, parent) {
			t.Fatalf("%s: JSONL below a denying folder accepted or unclear refusal: %s", tc.entry, got)
		}
	}
}
