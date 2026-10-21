// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
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
