//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"strings"
	"testing"

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
	if !strings.HasPrefix(sddl, "D:P(") || strings.Contains(sddl, ";BU)") || strings.Contains(sddl, ";WD)") ||
		!strings.Contains(sddl, "(A;OICI;0x1200a9;;;S-1-5-21-1111-2222-3333-1001)") ||
		!strings.Contains(sddl, "(A;OICI;0x1301bf;;;S-1-5-80-1-2-3-4-5)") {
		t.Fatalf("unexpected DACL %s", sddl)
	}
	if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
		t.Fatal(err)
	}
}
