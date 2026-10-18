// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/fsnotify/fsnotify"
)

// GAP-0045: a loop that rewrote only the Hermes hooks block in place reached
// a repair at the interval pass, 71 s later: the watch loop ignored every
// Write to a shared agent config. GAP-0044: an in-place overwrite of the
// scoped token right after a pass fell in the settle window and waited 24 s.
// A Write the writer policy or the settle window drops now counts when the
// file no longer holds what the last pass left there, and a pass's own tail
// (same bytes) is still dropped.
func TestEnterpriseHookWatchOwnedFileChangedSeesInPlaceRewrites(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	token := filepath.Join(dir, ".hook-hermes.token")
	other := filepath.Join(dir, "state.db")
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(config, "hooks:\n  pre_tool_call:\n  - command: defenseclaw\n")
	write(token, "issued\n")
	write(other, "x")
	exclusive := map[string]struct{}{token: {}}
	shared := map[string]struct{}{config: {}}
	snapshot := map[string]string{}
	takeEnterpriseHookOwnedSnapshot(snapshot, exclusive, shared, enterprisehooks.OwnedFileFingerprint)
	changed := func(path string) bool {
		return enterpriseHookWatchOwnedFileChanged(path, exclusive, shared, snapshot, enterprisehooks.OwnedFileFingerprint)
	}

	// The writer policy still drops a shared Write; the content check is what lets it through.
	if enterpriseHookWatchOwnedEventActionable(fsnotify.Event{Name: config, Op: fsnotify.Write}, exclusive, shared) {
		t.Fatal("a shared-writer Write became actionable by policy alone")
	}
	if changed(config) || changed(token) {
		t.Fatal("files as the pass left them read as changed (the pass's own tail)")
	}
	write(config, "hooks: {}\n")
	if !changed(config) {
		t.Fatal("an in-place rewrite of the shared agent config was not seen (GAP-0045)")
	}
	write(config, "hooks:\n  pre_tool_call:\n  - command: defenseclaw\n")
	if changed(config) {
		t.Fatal("a rewrite back to the same bytes read as changed")
	}
	write(token, "lane-made\n")
	if !changed(token) {
		t.Fatal("an in-place token overwrite was not seen (GAP-0044)")
	}
	if changed(other) {
		t.Fatal("an unowned file counted")
	}
	// An owned file the last pass did not fingerprint counts as changed.
	added := filepath.Join(dir, ".hookcfg.hermes")
	exclusive[added] = struct{}{}
	if !changed(added) {
		t.Fatal("an owned file without a snapshot did not count")
	}
	// The next pass's snapshot takes in what it left.
	takeEnterpriseHookOwnedSnapshot(snapshot, exclusive, shared, enterprisehooks.OwnedFileFingerprint)
	if changed(token) || changed(added) {
		t.Fatal("a fresh snapshot still reads changed")
	}
}
