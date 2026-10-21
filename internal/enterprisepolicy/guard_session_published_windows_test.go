//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
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
