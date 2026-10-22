// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
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
	// A repair of a root the hook trusts replaces it too and ends every
	// earlier allow the same way. (The test account stands in for the
	// gateway service, which the real check does not accept, so it is
	// replaced.)
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

// openWindowsHookSessionHandle opens path (the record root, a record
// folder, a record or the generation file) the way an account that had
// WRITE_DAC on it could, and keeps the handle: access is checked at open,
// so the handle keeps WRITE_DAC whatever DACL the object gets later.
func openWindowsHookSessionHandle(t *testing.T, path string, share uint32) windows.Handle {
	t.Helper()
	pointer, err := winpath.UTF16Ptr(path)
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

// windowsHookSessionTestOwner is the owner of path.
func windowsHookSessionTestOwner(t *testing.T, path string) *windows.SID {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

func windowsFileIndex(t *testing.T, handle windows.Handle) uint64 {
	t.Helper()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		t.Fatal(err)
	}
	return uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
}

// windowsHookSessionTestKey is the agent process the replacement tests
// publish for.
var windowsHookSessionTestKey = enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: "windows:b:1:100"}

// windowsHookSessionTestGeneration is the record root's current generation.
func windowsHookSessionTestGeneration(t *testing.T, root string) int64 {
	t.Helper()
	generation, err := enterprisepolicy.PublishedSessionGeneration(root)
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.ParseInt(generation, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// windowsHookSessionReplacementTestRoot is a record root as the lifecycle
// makes it, with an allow published for the test account. With drift it
// gets the drifted SDDL (standard users may add folders, delete them and
// change the DACL); without, the root keeps the trusted SDDL and the hook's
// root check accepts it (the test account stands in for the gateway
// service, which the real check does not accept).
func windowsHookSessionReplacementTestRoot(t *testing.T, drift bool) (root string, self *windows.SID, check func() error, drifted string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	self = user.User.Sid
	identity := self.String()
	root = filepath.Join(t.TempDir(), windowsHookSessionFolderName)
	// The holds are in the hook runtime folder next to the record folder.
	if holds, ok := enterprisepolicy.PublishedSessionHoldDir(root); !ok || os.MkdirAll(holds, 0o755) != nil {
		t.Fatalf("no hold folder for %s", root)
	}
	previousDir := windowsHookSessionDir
	windowsHookSessionDir = func() (string, error) { return root, nil }
	t.Cleanup(func() { windowsHookSessionDir = previousDir })
	if err := ensureWindowsHookSessionRoot(root, self); err != nil {
		t.Skipf("the record folder cannot get its owner here (an elevated test): %v", err)
	}
	key := windowsHookSessionTestKey
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
	if !drift {
		previousTrust := windowsHookSessionRootTrustProblem
		windowsHookSessionRootTrustProblem = func(string) error { return nil }
		t.Cleanup(func() { windowsHookSessionRootTrustProblem = previousTrust })
		return root, self, check, ""
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
	root, self, check, drifted := windowsHookSessionReplacementTestRoot(t, true)
	handle := openWindowsHookSessionHandle(t, root, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
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
	current := openWindowsHookSessionHandle(t, root, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
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
// again, whether the root was drifted or looked trusted. Once the handle is
// closed, the next repair replaces it.
func TestWindowsHookSessionRepairKeepsARootItCannotReplaceRefused(t *testing.T) {
	for name, drift := range map[string]bool{"drifted": true, "looks trusted": false} {
		t.Run(name, func(t *testing.T) { testWindowsHookSessionRepairKeepsARootItCannotReplaceRefused(t, drift) })
	}
}

func testWindowsHookSessionRepairKeepsARootItCannotReplaceRefused(t *testing.T, drift bool) {
	root, self, check, _ := windowsHookSessionReplacementTestRoot(t, drift)
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

// Review P1 (GAP-0352, 1.0.4 loop round 2): an administrator briefly gave
// an account WRITE_DAC on its own record folder, its record or the
// generation file; the account kept a handle and put the trusted DACL back,
// so the root looked right to the hook and to the repair. A repair that kept
// a root it trusted kept those objects, and after a guardian removal the
// handle let the account grant itself write access and put a fresh allow of
// the current generation in its record. Every repair and ensure now
// replaces the root with everything in it, even when it looks trusted: no
// object a retained handle reaches is at a record path afterwards, the old
// allow proves nothing, and the new generation is later than the old one.
// When a handle inside the root refuses the move, the step fails and the
// root keeps an owner the hook refuses instead.
func TestWindowsHookSessionRepairReplacesEveryObjectARetainedHandleReaches(t *testing.T) {
	root, self, check, _ := windowsHookSessionReplacementTestRoot(t, false)
	identity := self.String()
	key := windowsHookSessionTestKey
	account, _ := enterprisepolicy.PublishedSessionIdentityDir(root, identity)
	record, _ := enterprisepolicy.PublishedSessionRecordPath(root, identity, key.Connector, "p", key.Process)
	generation, _ := enterprisepolicy.PublishedSessionGenerationPath(root)
	before := windowsHookSessionTestGeneration(t, root)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	retained := map[string]uint64{}
	for _, path := range []string{root, account, record, generation} {
		retained[path] = windowsFileIndex(t, openWindowsHookSessionHandle(t, path, share))
	}
	if err := ensureWindowsHookSessionRoot(root, self); err != nil {
		if trusted, ownerErr := windowsPathOwnedByAdministrators(root); ownerErr != nil || trusted {
			t.Fatalf("a root the repair could not replace (%v) must keep an owner the hook refuses: %v %v", err, trusted, ownerErr)
		}
		t.Logf("the open handles refused the move; the root keeps an owner the hook refuses: %v", err)
		return
	}
	if err := check(); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("after the repair the old allow must prove nothing: %v", err)
	}
	if after := windowsHookSessionTestGeneration(t, root); after <= before {
		t.Fatalf("the new root's generation must be later than the replaced one: %d after %d", after, before)
	}
	// The gateway writes the account's folder and record again.
	if err := windowsHookSessionTestPublish(root, identity, key); err != nil {
		t.Fatal(err)
	}
	for path, index := range retained {
		if windowsFileIndex(t, openWindowsHookSessionHandle(t, path, share)) == index {
			t.Fatalf("%s is still the object a retained handle reaches", path)
		}
	}
	if trusted, err := windowsPathOwnedByAdministrators(root); err != nil || !trusted {
		t.Fatalf("the new root is owned by Administrators: %v %v", trusted, err)
	}
}

// The same with the record held open without delete sharing, which may
// refuse moving the root: either the root is replaced, or the step fails
// and the root keeps an owner the hook refuses. The old allow is never
// trusted again.
func TestWindowsHookSessionRepairWithARecordHeldOpen(t *testing.T) {
	root, self, check, _ := windowsHookSessionReplacementTestRoot(t, false)
	record, _ := enterprisepolicy.PublishedSessionRecordPath(root, self.String(), windowsHookSessionTestKey.Connector, "p", windowsHookSessionTestKey.Process)
	before := windowsFileIndex(t, openWindowsHookSessionHandle(t, root, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE))
	pointer, err := winpath.UTF16Ptr(record)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	if err := ensureWindowsHookSessionRoot(root, self); err != nil {
		if trusted, ownerErr := windowsPathOwnedByAdministrators(root); ownerErr != nil || trusted {
			t.Fatalf("a root the repair could not replace (%v) must keep an owner the hook refuses: %v %v", err, trusted, ownerErr)
		}
		return
	}
	if windowsFileIndex(t, openWindowsHookSessionHandle(t, root, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)) == before {
		t.Fatal("a repair that succeeded must have replaced the root")
	}
	if err := check(); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("after the repair the old allow must prove nothing: %v", err)
	}
}

// Review P2 (GAP-0352, 1.0.4 loop round 4): a lifecycle without
// SeRestorePrivilege cannot give the record root the retired owner. A
// retained handle with WRITE_DAC that does not share delete access refuses
// the move, so the step fails and the old root stays, with its generation
// file and allow. The handle then writes the trusted DACL back. The step
// leaves the records held, and status names the hold.
//
// Review P2 (GAP-0352, 1.0.4 guard loop round 2): the root then kept an
// Administrators owner, so the hold was all that kept the hook from the old
// allow, and an account that had also kept a handle on the hook runtime
// folder could delete it. The root now gets the lifecycle's own account as
// its owner, which the hook refuses and no WRITE_DAC handle can change:
// with the hold deleted and the trusted DACL written back, the root is
// still refused. Once the handle is gone, the next repair replaces the root
// and removes the hold, and the old allow proves nothing.
func TestWindowsHookSessionRepairWithoutTheRestorePrivilegeHoldsTheRecords(t *testing.T) {
	for name, drift := range map[string]bool{"drifted": true, "looks trusted": false} {
		t.Run(name, func(t *testing.T) {
			root, self, check, _ := windowsHookSessionReplacementTestRoot(t, drift)
			previous := windowsHookSessionOwnerRestorePrivilege
			windowsHookSessionOwnerRestorePrivilege = func(func() error) error {
				return errors.New("a required privilege is not held by the client")
			}
			t.Cleanup(func() { windowsHookSessionOwnerRestorePrivilege = previous })
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
			if !enterprisepolicy.PublishedSessionHeld(root) {
				t.Fatal("a step that could not replace the root must leave the records held")
			}
			if err := check(); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
				t.Fatalf("while the records are held the old allow must prove nothing: %v", err)
			}
			if problem := windowsHookSessionRootProblem(); !strings.Contains(problem, "is held") {
				t.Fatalf("status must name the hold: %q", problem)
			}
			// The account deletes the hold through a handle it kept on the
			// hook runtime folder.
			if err := enterprisepolicy.RemovePublishedSessionHolds(root); err != nil {
				t.Fatal(err)
			}
			if trusted, err := windowsPathOwnedByAdministrators(root); err != nil || trusted {
				t.Fatalf("a root the repair could not replace must keep an owner the hook refuses, hold or not: %v %v", trusted, err)
			}
			if owner := windowsHookSessionTestOwner(t, root); !windowsHookSessionOwnerRefused(owner) {
				t.Fatalf("the hook must refuse the owner %s of a root the repair could not replace", owner)
			}
			if problem := windowsHookSessionRootProblem(); !strings.Contains(problem, "not owned by Administrators or SYSTEM") {
				t.Fatalf("status must report the refused root: %q", problem)
			}
			closeHandle()
			windowsHookSessionOwnerRestorePrivilege = previous
			if err := ensureWindowsHookSessionRoot(root, self); err != nil {
				t.Fatal(err)
			}
			if enterprisepolicy.PublishedSessionHeld(root) {
				t.Fatal("the repair that replaced the root must remove the hold")
			}
			if err := check(); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
				t.Fatalf("the old allow must prove nothing: %v", err)
			}
			if err := windowsHookSessionTestPublish(root, self.String(), windowsHookSessionTestKey); err != nil {
				t.Fatal(err)
			}
			if err := check(); err != nil {
				t.Fatalf("the next allow proves the process: %v", err)
			}
		})
	}
}

// The lifecycle holds the records and refuses the root from its start
// (with its first bump), so a run that stops before the record step leaves
// them held and refused, and the record step that replaced the folder
// removes the hold. Uninstall removes it too.
func TestWindowsLifecycleHoldsTheRecordsFromItsStart(t *testing.T) {
	if !windowsEnterpriseIsElevated() {
		t.Skip("the lifecycle holds the records only when it runs elevated")
	}
	root, self, check, _ := windowsHookSessionReplacementTestRoot(t, false)
	bumpWindowsHookSessionGeneration("status")
	if enterprisepolicy.PublishedSessionHeld(root) {
		t.Fatal("status must not hold the records")
	}
	bumpWindowsHookSessionGeneration("repair")
	if !enterprisepolicy.PublishedSessionHeld(root) {
		t.Fatal("a repair must hold the records from its start")
	}
	if err := check(); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("while the records are held the allow must prove nothing: %v", err)
	}
	// 1.0.4 guard loop round 2: the root also gets an owner the hook
	// refuses from the start, so a run that stops before the record step
	// does not leave the hold as the only guard.
	if trusted, err := windowsPathOwnedByAdministrators(root); err != nil || trusted {
		t.Fatalf("a repair must give the root an owner the hook refuses from its start: %v %v", trusted, err)
	}
	if err := ensureWindowsHookSessionRoot(root, self); err != nil {
		t.Fatal(err)
	}
	if enterprisepolicy.PublishedSessionHeld(root) {
		t.Fatal("the record step must remove the hold")
	}
	bumpWindowsHookSessionGeneration("upgrade")
	if err := removeWindowsHookSessionRoot(); err != nil {
		t.Fatal(err)
	}
	if enterprisepolicy.PublishedSessionHeld(root) {
		t.Fatal("uninstall must remove the hold")
	}
}

// Review P2 (GAP-0352, 1.0.4 guard loop round 1): status names a hold the hook
// guardian left as well as the lifecycle's, and uninstall removes both.
func TestWindowsHookSessionStatusAndUninstallCoverTheGuardiansHold(t *testing.T) {
	root, self, _, _ := windowsHookSessionReplacementTestRoot(t, false)
	if err := enterprisepolicy.HoldPublishedSessionRemoval(root, self.String()); err != nil {
		t.Fatal(err)
	}
	removal, _ := enterprisepolicy.PublishedSessionRemovalHoldPath(root, self.String())
	if problem := windowsHookSessionRootProblem(); !strings.Contains(problem, "is held") || !strings.Contains(problem, removal) {
		t.Fatalf("status must name the guardian's hold %s: %q", removal, problem)
	}
	if err := ensureWindowsHookSessionRoot(root, self); err != nil {
		t.Fatal(err)
	}
	if !enterprisepolicy.PublishedSessionHeld(root) {
		t.Fatal("a repair leaves the guardian's hold to the guardian")
	}
	if err := removeWindowsHookSessionRoot(); err != nil {
		t.Fatal(err)
	}
	if enterprisepolicy.PublishedSessionHeld(root) {
		t.Fatal("uninstall must remove every hold")
	}
}
