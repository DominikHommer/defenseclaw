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

// Review P1 (GAP-0352, loop rounds 2 and 3): while the protected session
// record folder was writable by others, an account moved its own folder
// away, the guardian's revocation found nothing to revoke, and the account
// put the folder back after the repair checked the tree, before the folder
// was closed. The repair that puts the folder's mode back must not restore
// trust in the old records: it checks the tree before any folder is put
// back, closes it, and then invalidates every record it holds. A tree the
// hook trusts keeps its records.
func TestRepairInvalidatesHookSessionRecordsAnotherAccountCouldChange(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	root := h.env.P(h.env.Layout.HookSessionDir)
	var problem error
	var checked []string
	var afterCheck func()
	previous := hookSessionTreeProblem
	hookSessionTreeProblem = func(path string, _ enterprisepolicy.PublishedSessionTrust) error {
		checked = append(checked, path)
		if afterCheck != nil {
			afterCheck()
			afterCheck = nil
		}
		return problem
	}
	t.Cleanup(func() { hookSessionTreeProblem = previous })
	account, ok := enterprisepolicy.PublishedSessionIdentityDir(root, "1001")
	if !ok {
		t.Fatal("no account folder")
	}
	record := filepath.Join(account, "copilot-p-x.json")
	if err := os.MkdirAll(account, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
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
	afterCheck = func() {
		if err := os.Rename(aside, account); err != nil {
			t.Fatal(err)
		}
	}
	checked = nil
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if len(checked) == 0 || checked[0] != root {
		t.Fatalf("the tree must be checked before its mode is put back: %v", checked)
	}
	if exists(record) || exists(account) {
		t.Fatal("the folder the account brought back must be invalidated")
	}
	if info, err := os.Lstat(root); err != nil || info.Mode().Perm() != 0o711 {
		t.Fatalf("the folder's mode must be put back: %v %v", info, err)
	}
}

// Review P1 (GAP-0352, loop round 3): the repair invalidates the records
// only in a folder it closed, and it puts the owner back before the mode:
// an account that owned the folder could otherwise open it again between
// the two and bring a folder back while the records are invalidated.
func TestRepairClosesTheHookSessionRecordFolderBeforeItInvalidates(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	root := h.env.P(h.env.Layout.HookSessionDir)
	previousTree, previousInvalidate := hookSessionTreeProblem, hookSessionInvalidate
	hookSessionTreeProblem = func(string, enterprisepolicy.PublishedSessionTrust) error {
		return errors.New(root + " is owned by uid 1001")
	}
	var modes []os.FileMode
	hookSessionInvalidate = func(path string) error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		modes = append(modes, info.Mode().Perm())
		return previousInvalidate(path)
	}
	t.Cleanup(func() { hookSessionTreeProblem, hookSessionInvalidate = previousTree, previousInvalidate })
	// The account that owns the folder opens it again while it still can:
	// until the owner goes back.
	owned := true
	previousLchown := h.env.Lchown
	h.env.Lchown = func(path string, uid, gid int) error {
		if path == root && owned {
			owned = false
			if err := os.Chmod(root, 0o777); err != nil {
				return err
			}
		}
		return previousLchown(path, uid, gid)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if len(modes) != 1 || modes[0] != 0o700 {
		t.Fatalf("the records must be invalidated in a closed folder, got modes %v", modes)
	}
	if info, err := os.Lstat(root); err != nil || info.Mode().Perm() != 0o711 {
		t.Fatalf("the folder's mode must be put back: %v %v", info, err)
	}
}
