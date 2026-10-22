// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A planning cleanup lists the files it would edit and edits none. A
// cleanup limited to some files edits only those and reports, unedited,
// what it finds in any other file (also when the list is empty). JSON hook
// files, plugin directories and Hermes config.yaml all follow the scope.
func TestCleanupScopePlansAndLimitsEdits(t *testing.T) {
	t.Run("json hook file", func(t *testing.T) {
		req := guardRequest(t, "cursor", config.ForeignHooksRemove)
		path := filepath.Join(req.Home, ".cursor", "hooks.json")
		writeFile(t, path, `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`)
		checkCleanupScope(t, req, path)
	})
	t.Run("plugin directory", func(t *testing.T) {
		req := guardRequest(t, "opencode", config.ForeignHooksRemove)
		req.AccountHome = req.Home
		writeFile(t, filepath.Join(req.Home, ".config", "opencode", "plugins", "defenseclaw.js"), "// DefenseClaw")
		path := filepath.Join(req.Home, ".config", "opencode", "plugins", "mutate.js")
		writeFile(t, path, "export default {}")
		checkCleanupScope(t, req, path)
	})
	t.Run("hermes config", func(t *testing.T) {
		req, script := hermesGuardRequest(t, config.ForeignHooksRemove)
		path := filepath.Join(req.Home, ".hermes", "config.yaml")
		writeFile(t, path, hermesConfig(script, hermesRewriteEntry))
		checkCleanupScope(t, req, path)
	})
}

func checkCleanupScope(t *testing.T, req GuardRequest, path string) {
	t.Helper()
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := func() bool {
		data, err := os.ReadFile(path)
		return err == nil && string(data) == string(original)
	}
	plan, err := CleanUserForeignHooksWithRedirects(req, nil, CleanupScope{Plan: true}, time.Now())
	if err != nil || len(plan.Removed) != 0 || plan.BackupDir != "" || !slices.Equal(plan.Planned, []string{path}) || !unchanged() {
		t.Fatalf("a plan must list %s and edit nothing: %+v %v", path, plan, err)
	}
	for _, files := range [][]string{{}, {filepath.Join(req.Home, "another.json")}} {
		result, err := CleanUserForeignHooksWithRedirects(req, nil, CleanupScope{Files: files}, time.Now())
		if err != nil || len(result.Removed) != 0 || len(result.Planned) != 0 || !unchanged() ||
			!slices.ContainsFunc(result.Reported, func(f Finding) bool { return f.Path == path && strings.Contains(f.Reason, "next pass") }) {
			t.Fatalf("a cleanup limited to %v edited or did not report %s: %+v %v", files, path, result, err)
		}
	}
	result, err := CleanUserForeignHooksWithRedirects(req, nil, CleanupScope{Files: plan.Planned}, time.Now())
	if err != nil || len(result.Removed) == 0 || unchanged() {
		t.Fatalf("a cleanup of the planned file did not clean it: %+v %v", result, err)
	}
	for _, finding := range result.Removed {
		if finding.Path != path {
			t.Fatalf("the cleanup removed %s outside its planned file", finding.Path)
		}
	}
}
