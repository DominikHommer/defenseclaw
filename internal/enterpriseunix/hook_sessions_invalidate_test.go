// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// Review P1 (GAP-0352, loop round 2): while the protected session record
// folder was writable by others, an account moved its own folder away, the
// guardian's revocation found nothing to revoke, and the account put the
// folder back. The repair that puts the folder's mode back must not restore
// trust in the old records: it invalidates them first and keeps the
// guardian's holds. A tree the hook trusts keeps its records.
func TestRepairInvalidatesHookSessionRecordsAnotherAccountCouldChange(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	root := h.env.P(h.env.Layout.HookSessionDir)
	var problem error
	var checked []string
	previous := hookSessionTreeProblem
	hookSessionTreeProblem = func(path string, _ enterprisepolicy.PublishedSessionTrust) error {
		checked = append(checked, path)
		return problem
	}
	t.Cleanup(func() { hookSessionTreeProblem = previous })
	account, ok := enterprisepolicy.PublishedSessionIdentityDir(root, "1001")
	if !ok {
		t.Fatal("no account folder")
	}
	record := filepath.Join(account, "copilot-p-x.json")
	hold := account + ".hold"
	if err := os.MkdirAll(account, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{record, hold} {
		if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if !exists(record) {
		t.Fatal("a tree the hook trusts must keep its records")
	}

	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	problem = errors.New(root + " is writable by group or other (0777)")
	aside := filepath.Join(filepath.Dir(root), "aside")
	if err := os.Rename(account, aside); err != nil {
		t.Fatal(err)
	}
	if err := enterprisepolicy.RemovePublishedForeignHookSessions(root, "1001", []string{"copilot"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(aside, account); err != nil {
		t.Fatal(err)
	}
	checked = nil
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if len(checked) == 0 || checked[0] != root {
		t.Fatalf("the tree must be checked before its mode is put back: %v", checked)
	}
	if exists(record) {
		t.Fatal("the record the account brought back must be invalidated")
	}
	if !exists(hold) {
		t.Fatal("the guardian's hold must stay")
	}
	if info, err := os.Lstat(root); err != nil || info.Mode().Perm() != 0o711 {
		t.Fatalf("the folder's mode must be put back: %v %v", info, err)
	}
}
