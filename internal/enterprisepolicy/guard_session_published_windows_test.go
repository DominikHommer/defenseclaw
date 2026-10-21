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
// replacement and the guardian's deletion. The block and the removal must
// still deny through the record's deny marker.
func TestPublishedSessionRecordHeldOpenWithoutDeleteSharingIsStillRevoked(t *testing.T) {
	root := t.TempDir()
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "windows:b:1:100"}
	check := func() (GuardDecision, error) {
		t.Helper()
		return CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
	}
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
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
	_ = PublishForeignHookSessionDecision(root, identity, key, GuardDecision{Deny: true, Reason: reason}, time.Now())
	if got, err := check(); err != nil || !got.Deny || got.Reason != reason {
		_ = windows.CloseHandle(handle)
		t.Fatalf("a block of a held record must deny: %+v %v", got, err)
	}
	_ = windows.CloseHandle(handle)
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := check(); err != nil || got.Deny {
		t.Fatalf("the replacing allow must clear the marker: %+v %v", got, err)
	}
	handle = hold()
	defer func() { _ = windows.CloseHandle(handle) }()
	if err := RemovePublishedForeignHookSessions(root, identity, []string{"copilot"}); err != nil {
		t.Fatal(err)
	}
	if got, err := check(); err != nil || !got.Deny {
		t.Fatalf("the guardian's removal of a held record must deny: %+v %v", got, err)
	}
	if err := WithdrawPublishedForeignHookSession(root, identity, key); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if got, err := check(); err != nil || !got.Deny {
		t.Fatalf("a withdrawn answer of a held record must deny: %+v %v", got, err)
	}
}
