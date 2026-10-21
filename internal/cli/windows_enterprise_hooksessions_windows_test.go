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
	"github.com/defenseclaw/defenseclaw/internal/winpath"
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

// windowsHookSessionTestPublish publishes an allow as the gateway does,
// stamped with the generation it reads first.
func windowsHookSessionTestPublish(root, identity string, key enterprisepolicy.SessionKey) error {
	generation, err := enterprisepolicy.PublishedSessionGeneration(root)
	if err != nil {
		return err
	}
	return enterprisepolicy.PublishForeignHookSessionDecision(root, identity, key, enterprisepolicy.GuardDecision{}, generation, time.Now())
}

// Review P1 (GAP-0352, loop round 2; lead directive, loop round 1), on real
// folders: while the record root let standard users add and delete
// folders, the account moved its folder aside during a guardian removal and
// put it back. Until the repair the hook refuses the tree; the repair that
// restores the root's access must not let the hook trust the old allow
// again. The generation bump ends it, and a repair of a root nobody
// loosened ends every earlier allow the same way.
func TestWindowsHookSessionRepairEndsRecordsMovedAsideAndBack(t *testing.T) {
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
	if err := windowsHookSessionTestPublish(root, identity, key); err != nil {
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
	if windowsHookSessionRootTrustProblem(root) == nil {
		t.Fatal("a root standard users can add folders to and delete them from must be a problem")
	}
	account, _ := enterprisepolicy.PublishedSessionIdentityDir(root, identity)
	aside := filepath.Join(base, "aside")
	if err := os.Rename(account, aside); err != nil {
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
	if err := windowsHookSessionTestPublish(root, identity, key); err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil {
		t.Fatalf("the next allow after the repair proves the process: %v", err)
	}
	// A repair of a root the hook trusts keeps the folder and still ends
	// every earlier allow. (The test account stands in for the gateway
	// service, which the real check does not accept, so it is replaced.)
	previousTrust := windowsHookSessionRootTrustProblem
	windowsHookSessionRootTrustProblem = func(string) error { return nil }
	t.Cleanup(func() { windowsHookSessionRootTrustProblem = previousTrust })
	if err := ensureWindowsHookSessionRoot(root, self); err != nil {
		t.Fatal(err)
	}
	if err := check(); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("after a repair of a trusted root the old allow must prove nothing: %v", err)
	}
}

// Review P2 (GAP-0352, loop round 3): status and verify check the record
// folder with the hook's own rule (windowsHookSessionRootTrustProblem), so a
// drift the hook refuses, such as a Cisco folder above it that standard
// users can delete children of, is reported as
// hook_session_records_untrusted, and so is a generation file the hook
// refuses. The advisory ancestor verdicts of
// ValidateTrustedServiceRuntimeDir hid the first.
func TestWindowsHookSessionStatusUsesTheHooksStrictRule(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), windowsHookSessionFolderName)
	var drift error
	var checked []string
	previousDir, previousTree, previousGeneration := windowsHookSessionDir, windowsHookSessionRootTrustProblem, windowsHookSessionGenerationProblem
	windowsHookSessionDir = func() (string, error) { return root, nil }
	windowsHookSessionRootTrustProblem = func(path string) error {
		checked = append(checked, path)
		return drift
	}
	t.Cleanup(func() {
		windowsHookSessionDir, windowsHookSessionRootTrustProblem, windowsHookSessionGenerationProblem = previousDir, previousTree, previousGeneration
	})
	windowsHookSessionGenerationProblem = func(string) error { return nil }
	if err := ensureWindowsHookSessionRoot(root, user.User.Sid); err != nil {
		t.Skipf("the record folder cannot get its owner here (an elevated test): %v", err)
	}
	if problem := windowsHookSessionRootProblem(); problem != "" {
		t.Fatalf("a folder the hook trusts must be no problem: %s", problem)
	}
	drift = errors.New(`C:\ProgramData\Cisco lets BUILTIN\Users delete its children`)
	checked = nil
	problem := windowsHookSessionRootProblem()
	if !strings.Contains(problem, "delete its children") || len(checked) != 1 || checked[0] != root {
		t.Fatalf("a drift the hook refuses must be reported (checked %v): %q", checked, problem)
	}
	// A generation file the hook refuses is reported too.
	drift = nil
	windowsHookSessionGenerationProblem = func(string) error { return errors.New("the generation file is owned by BUILTIN\\Users") }
	if problem := windowsHookSessionRootProblem(); !strings.Contains(problem, "generation file is owned") {
		t.Fatalf("a refused generation file must be reported: %q", problem)
	}
}

// openWindowsHookSessionRootHandle opens root the way an account that had
// WRITE_DAC on it could, and keeps the handle: access is checked at open,
// so the handle keeps WRITE_DAC whatever DACL the folder gets later.
func openWindowsHookSessionRootHandle(t *testing.T, root string, share uint32) windows.Handle {
	t.Helper()
	pointer, err := winpath.UTF16Ptr(root)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pointer, windows.READ_CONTROL|windows.WRITE_DAC, share, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	return handle
}

// setWindowsDACLThroughHandle writes the DACL of sddl through handle, as
// the account with the retained handle would.
func setWindowsDACLThroughHandle(t *testing.T, handle windows.Handle, sddl string) error {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func windowsFileIndex(t *testing.T, handle windows.Handle) uint64 {
	t.Helper()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		t.Fatal(err)
	}
	return uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
}

// windowsHookSessionReplacementTestRoot is a record root as the lifecycle
// makes it, with an allow published for the test account, and its drifted
// SDDL: standard users may add folders, delete them and change the DACL.
func windowsHookSessionReplacementTestRoot(t *testing.T) (root string, self *windows.SID, check func() error, drifted string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	self = user.User.Sid
	identity := self.String()
	root = filepath.Join(t.TempDir(), windowsHookSessionFolderName)
	previousDir := windowsHookSessionDir
	windowsHookSessionDir = func() (string, error) { return root, nil }
	t.Cleanup(func() { windowsHookSessionDir = previousDir })
	if err := ensureWindowsHookSessionRoot(root, self); err != nil {
		t.Skipf("the record folder cannot get its owner here (an elevated test): %v", err)
	}
	key := enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: "windows:b:1:100"}
	if err := windowsHookSessionTestPublish(root, identity, key); err != nil {
		t.Fatal(err)
	}
	check = func() error {
		_, err := enterprisepolicy.CheckPublishedForeignHookSession(root, identity, key, enterprisepolicy.GuardDecision{}, func(string) error { return nil })
		return err
	}
	if err := check(); err != nil {
		t.Fatalf("the published allow must prove the process: %v", err)
	}
	drifted = "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x40044;;;BU)(A;OICI;0x1301bf;;;" + self.String() + ")"
	if err := applyWindowsSDDL(root, drifted); err != nil {
		t.Fatal(err)
	}
	if windowsHookSessionRootTrustProblem(root) == nil {
		t.Fatal("a root standard users can change must be a problem")
	}
	return root, self, check, drifted
}

// Review P1 (GAP-0352, loop round 4): while the record root gave standard
// users WRITE_DAC and the right to move folders, an account kept a handle
// with WRITE_DAC on it. Changing the DACL of that same folder object did
// not take the access away: through the handle, the account could open the
// folder again after the invalidation and bring its folder back before the
// final DACL. The repair now replaces the folder object: the folder at the
// root path is a new one, the handle's DACL changes never reach it, and the
// old allow proves nothing.
func TestWindowsHookSessionRepairReplacesARootARetainedHandleCanChange(t *testing.T) {
	root, self, check, drifted := windowsHookSessionReplacementTestRoot(t)
	handle := openWindowsHookSessionRootHandle(t, root, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	before := windowsFileIndex(t, handle)
	if err := ensureWindowsHookSessionRoot(root, self); err != nil {
		t.Fatal(err)
	}
	// The account uses its handle to open the folder again. The retired
	// folder may already be deleted (pending its last handle), which
	// refuses that; either way the folder at the root path is another one.
	if err := setWindowsDACLThroughHandle(t, handle, drifted); err != nil {
		t.Logf("the retained handle cannot change the retired folder any more: %v", err)
	}
	current := openWindowsHookSessionRootHandle(t, root, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if windowsFileIndex(t, current) == before {
		t.Fatal("the repair must replace the folder object a retained handle can change")
	}
	if windowsHookSessionRootTrustProblem(root) != nil {
		t.Fatalf("the new root must be one the hook trusts: %v", windowsHookSessionRootTrustProblem(root))
	}
	if trusted, err := windowsPathOwnedByAdministrators(root); err != nil || !trusted {
		t.Fatalf("the new root is owned by Administrators: %v %v", trusted, err)
	}
	if err := check(); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("after the repair the old allow must prove nothing: %v", err)
	}
}

// The same with a handle that does not share delete access, which refuses
// the move: the repair fails and the folder keeps an owner the hook refuses
// whatever the handle writes into its DACL, so nothing it holds is trusted
// again. Once the handle is closed, the next repair replaces it.
func TestWindowsHookSessionRepairKeepsARootItCannotReplaceRefused(t *testing.T) {
	root, self, check, _ := windowsHookSessionReplacementTestRoot(t)
	pointer, err := winpath.UTF16Ptr(root)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pointer, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	closeHandle := func() {
		if !closed {
			closed = true
			_ = windows.CloseHandle(handle)
		}
	}
	t.Cleanup(closeHandle)
	if err := ensureWindowsHookSessionRoot(root, self); err == nil {
		t.Fatal("a root that cannot be moved aside must fail the step")
	}
	// The account writes the trusted DACL back through its handle.
	if err := setWindowsDACLThroughHandle(t, handle, windowsHookSessionSDDL(self)); err != nil {
		t.Fatal(err)
	}
	if trusted, err := windowsPathOwnedByAdministrators(root); err != nil || trusted {
		t.Fatalf("a root the repair could not replace must keep an owner the hook refuses: %v %v", trusted, err)
	}
	if problem := windowsHookSessionRootProblem(); problem == "" {
		t.Fatal("status must report the refused root")
	}
	closeHandle()
	if err := ensureWindowsHookSessionRoot(root, self); err != nil {
		t.Fatal(err)
	}
	if trusted, err := windowsPathOwnedByAdministrators(root); err != nil || !trusted {
		t.Fatalf("the next repair replaces it: %v %v", trusted, err)
	}
	if err := check(); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("the old allow must prove nothing: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(root))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), windowsHookSessionRetiredInfix) {
			t.Fatalf("a retired root must not be left behind: %s", entry.Name())
		}
	}
}
