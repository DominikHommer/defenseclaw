// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// GAP-0352: the protected session record folder is owned by Administrators;
// SYSTEM and Administrators have full control, the gateway service modify,
// and standard users only read and list this folder (their own folder below
// has its own DACL). Nobody else has access.
func TestWindowsHookSessionFolderSDDL(t *testing.T) {
	gateway, err := windows.StringToSid("S-1-5-80-1-2-3-4-5")
	if err != nil {
		t.Fatal(err)
	}
	sddl := windowsHookSessionSDDL(gateway)
	for _, want := range []string{"O:BAG:SYD:P", "(A;OICI;FA;;;SY)", "(A;OICI;FA;;;BA)", "(A;;0x1200a9;;;BU)", "(A;OICI;0x1301bf;;;S-1-5-80-1-2-3-4-5)"} {
		if !strings.Contains(sddl, want) {
			t.Fatalf("%s lacks %s", sddl, want)
		}
	}
	if strings.Count(sddl, "(A;") != 4 || strings.Contains(sddl, "(D;") {
		t.Fatalf("unexpected entries in %s", sddl)
	}
	if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
		t.Fatal(err)
	}
}

// Review P1 (GAP-0352, loop round 2), on real folders: while the record
// root let standard users add and delete folders, the account moved its
// folder aside, the guardian's removal found nothing to revoke, and the
// account put the folder back. Until the repair the hook refuses the tree;
// the repair that restores the root's access must not let the hook trust
// the old allow again, so it invalidates the records first.
func TestWindowsHookSessionRepairInvalidatesRecordsMovedAsideAndBack(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	self := user.User.Sid
	identity := self.String()
	base := t.TempDir()
	root := filepath.Join(base, windowsHookSessionFolderName)
	previousDir := windowsHookSessionDir
	windowsHookSessionDir = func() (string, error) { return root, nil }
	t.Cleanup(func() { windowsHookSessionDir = previousDir })
	if err := ensureWindowsHookSessionRoot(root, self); err != nil {
		t.Skipf("the record folder cannot get its owner here (an elevated test): %v", err)
	}
	key := enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: "windows:b:1:100"}
	if err := enterprisepolicy.PublishForeignHookSessionDecision(root, identity, key, enterprisepolicy.GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	check := func() error {
		t.Helper()
		_, err := enterprisepolicy.CheckPublishedForeignHookSession(root, identity, key, enterprisepolicy.GuardDecision{}, func(string) error { return nil })
		return err
	}
	if err := check(); err != nil {
		t.Fatalf("the published allow must prove the process: %v", err)
	}
	drifted := "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x44;;;BU)(A;OICI;0x1301bf;;;" + self.String() + ")"
	if err := applyWindowsSDDL(root, drifted); err != nil {
		t.Fatal(err)
	}
	if windowsHookSessionTreeProblem(root) == nil {
		t.Fatal("a root standard users can add folders to and delete them from must be a problem")
	}
	account, _ := enterprisepolicy.PublishedSessionIdentityDir(root, identity)
	aside := filepath.Join(base, "aside")
	if err := os.Rename(account, aside); err != nil {
		t.Fatal(err)
	}
	if err := enterprisepolicy.RemovePublishedForeignHookSessions(root, identity, []string{"copilot"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(aside, account); err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsHookSessionRoot(root, self); err != nil {
		t.Fatal(err)
	}
	if err := check(); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("after the repair the old allow must prove nothing: %v", err)
	}
	if err := enterprisepolicy.PublishForeignHookSessionDecision(root, identity, key, enterprisepolicy.GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil {
		t.Fatalf("the next allow after the repair proves the process: %v", err)
	}
}
