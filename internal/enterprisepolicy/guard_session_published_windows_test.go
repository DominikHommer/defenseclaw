//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func withoutPublishedSessionACL(*testing.T) {}

func publishedSessionTestIdentity(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return strings.ToUpper(user.User.Sid.String())
}

func publishedSessionOtherIdentity(string) string { return "S-1-5-21-1111-2222-3333-4242" }

// The per-account folder's protected DACL: SYSTEM and Administrators full,
// the gateway (this process) modify, the account read, nobody else.
func TestPublishedSessionDirSDDLGrantsOnlyTheAccountRead(t *testing.T) {
	service, _ := windows.StringToSid("S-1-5-80-1-2-3-4-5")
	account, _ := windows.StringToSid("S-1-5-21-1111-2222-3333-1001")
	sddl := publishedSessionDirSDDL(service, account)
	if !strings.HasPrefix(sddl, "O:S-1-5-80-1-2-3-4-5D:P(") || strings.Contains(sddl, ";BU)") || strings.Contains(sddl, ";WD)") ||
		!strings.Contains(sddl, "(A;OICI;0x1200a9;;;S-1-5-21-1111-2222-3333-1001)") ||
		!strings.Contains(sddl, "(A;OICI;0x1301bf;;;S-1-5-80-1-2-3-4-5)") {
		t.Fatalf("unexpected DACL %s", sddl)
	}
	if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
		t.Fatal(err)
	}
}

// Review P1 (GAP-0352), on a real Windows file: the account opens its allow
// record for reading without FILE_SHARE_DELETE, which refuses the gateway's
// replacement and deletion. A block, of the session or of the process alone,
// must still deny through the record's deny marker.
func TestPublishedSessionRecordHeldOpenWithoutDeleteSharingIsStillRevoked(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "windows:b:1:100"}
	check := func() (GuardDecision, error) {
		t.Helper()
		return CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
	}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(); err != nil || got.Deny {
		t.Fatalf("the allow must prove the process unblocked: %+v %v", got, err)
	}
	path, ok := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	if !ok {
		t.Fatal("no record path")
	}
	hold := func() windows.Handle {
		t.Helper()
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			t.Fatal(err)
		}
		return handle
	}
	handle := hold()
	if err := os.Remove(path); err == nil {
		t.Fatal("the held record must refuse its deletion")
	}
	reason := foreignHookBlockedPrefix + " the project hook"
	_ = publishCurrent(root, identity, key, GuardDecision{Deny: true, Reason: reason}, time.Now())
	if got, err := check(); err != nil || !got.Deny || got.Reason != reason {
		_ = windows.CloseHandle(handle)
		t.Fatalf("a block of a held record must deny: %+v %v", got, err)
	}
	_ = windows.CloseHandle(handle)
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(); err != nil || got.Deny {
		t.Fatalf("the replacing allow must clear the marker: %+v %v", got, err)
	}
	handle = hold()
	defer func() { _ = windows.CloseHandle(handle) }()
	_ = publishCurrent(root, identity, SessionKey{Connector: key.Connector, Process: key.Process}, GuardDecision{Deny: true}, time.Now())
	if got, err := check(); err != nil || !got.Deny {
		t.Fatalf("a block of the held process record must deny: %+v %v", got, err)
	}
}

// Review P1 (GAP-0352), on a real Windows file: a held record whose deny
// marker cannot be created (a full volume) is still revoked. Its
// modification time is set through an attributes-only handle, which the
// reader's sharing mode does not refuse, and the hook refuses the expired
// record.
func TestPublishedSessionRecordHeldOpenIsRevokedWithoutItsMarker(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "windows:b:1:100"}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	path, ok := PublishedSessionRecordPath(root, identity, "copilot", sessionKindProcess, key.Process)
	if !ok {
		t.Fatal("no record path")
	}
	previousCreate := publishedSessionCreate
	publishedSessionCreate = func(name string) (*os.File, error) {
		return nil, &os.PathError{Op: "open", Path: name, Err: windows.ERROR_DISK_FULL}
	}
	t.Cleanup(func() { publishedSessionCreate = previousCreate })
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	// No sharing at all: the strictest hold a reader can take.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	if err := revokePublishedSessionRecord(path, PublishedSessionRecord{Version: publishedSessionVersion, Connector: "copilot", Kind: sessionKindProcess, ID: key.Process, Blocked: true}); err != nil {
		t.Fatalf("the expired record is a revocation: %v", err)
	}
	if _, err := os.Lstat(publishedSessionDenyPath(path)); !os.IsNotExist(err) {
		t.Fatalf("no marker can exist: %v", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		t.Fatal(err)
	}
	if modified := time.Unix(0, info.LastWriteTime.Nanoseconds()); modified.After(publishedSessionRevokedTime.Add(time.Second)) {
		t.Fatalf("the held record must be expired, modified %v", modified)
	}
	if got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll); err == nil && !got.Deny {
		t.Fatalf("the expired held record must not prove the allow: %+v", got)
	}
}

// Lead directive (GAP-0352 review loop round 1), on a real Windows file: an
// account that holds the generation file open with no sharing at all cannot
// stop a bump. It moves the modification time through an attributes-only
// handle, and the allow written before it proves nothing.
func TestPublishedSessionGenerationHeldOpenStillBumps(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "windows:b:1:100"}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	path, _ := PublishedSessionGenerationPath(root)
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	before := publishedSessionTestGeneration(t, root)
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	if after := publishedSessionTestGeneration(t, root); after <= before {
		t.Fatalf("a held generation file must still move forward: %d after %d", after, before)
	}
	if _, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("the allow from before the bump must prove nothing: %v", err)
	}
}

// Review (GAP-0352, 1.0.4 loop round 4): the hold file gives standard users
// no access, so no account can open it and keep it from being removed; the
// hook still sees it, and the release removes it.
func TestPublishedSessionHoldGivesStandardUsersNoAccess(t *testing.T) {
	root := t.TempDir()
	publishedSessionTestHoldDir(t, root)
	if err := HoldPublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	hold, _ := PublishedSessionHoldPath(root)
	descriptor, err := windows.GetNamedSecurityInfo(hold, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := descriptor.String()
	if !strings.Contains(sddl, "D:P") || strings.Contains(sddl, ";BU)") || strings.Contains(sddl, ";WD)") || strings.Contains(sddl, ";AU)") {
		t.Fatalf("the hold must be closed to standard users: %s", sddl)
	}
	if !PublishedSessionHeld(root) {
		t.Fatal("the hold must be seen")
	}
	if err := ReleasePublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	if PublishedSessionHeld(root) {
		t.Fatal("the release must remove the hold")
	}
}

// Review P2 (GAP-0352, 1.0.4 guard loop round 1): the holds are in the hook
// runtime folder, to which only SYSTEM and Administrators can add a file,
// not in the Cisco folder above the record folder, where a stock
// ProgramData access list lets a standard user create one first.
func TestPublishedSessionHoldIsInTheHookRuntimeFolder(t *testing.T) {
	layout, err := managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	hold, ok := PublishedSessionHoldPath(layout.HookSessionDir)
	if !ok || !strings.EqualFold(filepath.Dir(hold), layout.HookRuntimeDir) {
		t.Fatalf("the lifecycle's hold must be in %s: %q", layout.HookRuntimeDir, hold)
	}
	removal, ok := PublishedSessionRemovalHoldPath(layout.HookSessionDir, "S-1-5-21-1-2-3-1001")
	if !ok || !strings.EqualFold(filepath.Dir(removal), layout.HookRuntimeDir) {
		t.Fatalf("the guardian's hold must be in %s: %q", layout.HookRuntimeDir, removal)
	}
}

// Review P2 (GAP-0352, 1.0.4 guard loop round 1): a file at the hold path whose
// DACL lets another account change or delete it (a standard user's own
// file) is replaced by a hold closed to them before the run changes
// anything; the run never keeps it as its hold.
func TestPublishedSessionHoldReplacesAFileOthersMayDelete(t *testing.T) {
	root := t.TempDir()
	publishedSessionTestHoldDir(t, root)
	hold, _ := PublishedSessionHoldPath(root)
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	attributes := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	pointer, err := winpath.UTF16Ptr(hold)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, attributes,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = windows.CloseHandle(handle)
	if publishedSessionHoldTrusted(hold) {
		t.Fatal("a file everyone may delete is no hold DefenseClaw made")
	}
	if err := HoldPublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionHoldTrusted(hold) {
		t.Fatal("the run must replace it with its own hold")
	}
	current, err := windows.GetNamedSecurityInfo(hold, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if sddl := current.String(); strings.Contains(sddl, ";WD)") {
		t.Fatalf("the new hold must be closed to everyone else: %s", sddl)
	}
}

// Review P2 (GAP-0352, 1.0.4 guard loop round 3): a lifecycle that can give
// a record folder it cannot replace no owner the hook refuses (SYSTEM
// without SeRestorePrivilege) refuses it with a file next to it, outside
// the record folder and the hook runtime folder. While it is there the
// records are held, whatever is in the hold folder; a second refusal keeps
// the first; standard users may only read its attributes and owner; a file
// with the refusal's name that others may change is ignored; and the
// release after a replacement removes it.
func TestPublishedSessionRootRefusalHoldsUntilTheRelease(t *testing.T) {
	root := filepath.Join(t.TempDir(), managed.StandaloneWindowsHookSessionDirName)
	publishedSessionTestHoldDir(t, root)
	if PublishedSessionHeld(root) {
		t.Fatal("nothing holds the records yet")
	}
	parent := filepath.Dir(root)
	junk := filepath.Join(parent, filepath.Base(root)+publishedSessionRefusalInfix+"junk")
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	attributes := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	pointer, err := winpath.UTF16Ptr(junk)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, attributes,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = windows.CloseHandle(handle)
	if PublishedSessionHeld(root) {
		t.Fatal("a file everyone may change is no refusal")
	}
	if err := RefusePublishedSessionRoot(root); err != nil {
		t.Fatal(err)
	}
	refusals, err := publishedSessionRootRefusals(root)
	if err != nil || len(refusals) != 1 || !strings.EqualFold(filepath.Dir(refusals[0]), parent) {
		t.Fatalf("one refusal next to the record folder: %v %v", refusals, err)
	}
	if !PublishedSessionHeld(root) {
		t.Fatal("the refusal holds the records")
	}
	if holds, err := os.ReadDir(publishedSessionHoldDir(root)); err != nil || len(holds) != 0 {
		t.Fatalf("the refusal is not in the hold folder: %v %v", holds, err)
	}
	current, err := windows.GetNamedSecurityInfo(refusals[0], windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if sddl := current.String(); !strings.Contains(sddl, "D:P") || strings.Contains(sddl, ";WD)") || strings.Contains(sddl, "FA;;;BU)") {
		t.Fatalf("standard users may only read the refusal's attributes and owner: %s", sddl)
	}
	if err := RefusePublishedSessionRoot(root); err != nil {
		t.Fatal(err)
	}
	if again, err := publishedSessionRootRefusals(root); err != nil || len(again) != 1 {
		t.Fatalf("a refusal in place is kept: %v %v", again, err)
	}
	if err := ReleasePublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	if PublishedSessionHeld(root) {
		t.Fatal("the release after a replacement removes the refusal")
	}
}
