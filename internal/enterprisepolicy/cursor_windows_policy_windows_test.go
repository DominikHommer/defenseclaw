//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The standalone guardian keeps Cursor's machine hook published even when
// no user is enrolled. Verify reports an absent hooks.json as drift and names
// the action required to restore protection.
func TestWindowsCursorVerifyReportsMissingMachineHook(t *testing.T) {
	opts := windowsTestOptions(t)
	state, err := cursorTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Join(opts.WindowsProgramData, "Cursor", "hooks.json")
	if state.Covered || len(state.Conflicts) != 1 {
		t.Fatalf("state = %+v, want one conflict and not covered", state)
	}
	want := hooks + " does not exist: Cursor's configured machine hook is missing; this is a protection failure"
	if !strings.HasPrefix(state.Conflicts[0], want) {
		t.Fatalf("conflict = %q, want it to start with %q", state.Conflicts[0], want)
	}
	for _, action := range []string{"Stop Cursor use until repaired", "enterprise windows reconcile --profile standalone", "enterprise windows repair --profile standalone"} {
		if !strings.Contains(state.Conflicts[0], action) {
			t.Errorf("conflict = %q, want %q", state.Conflicts[0], action)
		}
	}
}

// A hooks.json an earlier release published registers afterAgentThought. It
// still counts as DefenseClaw's registration (presence, no flap conflict) and
// the next reconcile rewrites it without that event; removal strips it too.
func TestWindowsCursorReconcileRepairsPreRetirementAfterAgentThought(t *testing.T) {
	opts := windowsTestOptions(t)
	if _, err := (cursorTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	hooksPath, adapterPath, err := windowsCursorPaths(opts)
	if err != nil {
		t.Fatal(err)
	}
	current, exists, err := readPolicyFile(opts, hooksPath)
	if err != nil || !exists {
		t.Fatalf("published hooks.json: exists=%v err=%v", exists, err)
	}
	if bytes.Contains(current, []byte("afterAgentThought")) {
		t.Fatalf("reconcile registered afterAgentThought:\n%s", current)
	}

	var doc map[string]any
	if err := json.Unmarshal(current, &doc); err != nil {
		t.Fatal(err)
	}
	hooks := doc["hooks"].(map[string]any)
	hooks["afterAgentThought"] = hooks["preToolUse"]
	legacy, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writePolicyFile(opts, hooksPath, legacy); err != nil {
		t.Fatal(err)
	}
	if present, err := MachinePolicyPresent(opts, ConnectorCursor); err != nil || !present {
		t.Fatalf("pre-retirement policy presence = %v, %v; want true", present, err)
	}
	if err := connector.VerifyWindowsCursorEnterpriseHooks(legacy, adapterPath, "closed"); err == nil {
		t.Fatal("strict verifier accepted the pre-retirement policy")
	}

	state, err := cursorTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if !state.Changed {
		t.Fatalf("reconcile left the pre-retirement policy in place: %+v", state)
	}
	repaired, _, err := readPolicyFile(opts, hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(repaired, []byte("afterAgentThought")) {
		t.Fatalf("reconcile kept afterAgentThought:\n%s", repaired)
	}
	if err := connector.VerifyWindowsCursorEnterpriseHooks(repaired, adapterPath, "closed"); err != nil {
		t.Fatalf("repaired policy: %v", err)
	}

	if _, err := writePolicyFile(opts, hooksPath, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := (cursorTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	left, exists, err := readPolicyFile(opts, hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(left, adapterPath)
		if err != nil || !connector.WindowsCursorEnterpriseHooksSemanticallyEqual(cleaned, left) {
			t.Fatalf("removal left DefenseClaw entries (err=%v):\n%s", err, left)
		}
	}
}
