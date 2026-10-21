// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"
	"time"
)

// A redirected AppData value is used when it names a local folder; the
// profile's own folder, a network share and other variables are not
// (GAP-1249).
func TestRedirectedAppDataFolder(t *testing.T) {
	const home = `C:\Users\alice`
	for _, tc := range []struct {
		value, folder string
		refused       bool
	}{
		{`%USERPROFILE%\AppData\Roaming`, "", false},
		{`c:\users\ALICE\AppData\Roaming\`, "", false},
		{`D:\Redirected\%USERNAME%\Roaming`, `D:\Redirected\alice\Roaming`, false},
		{`%userprofile%\Documents\AppData`, `C:\Users\alice\Documents\AppData`, false},
		{`D:\Redirected\alice\..\bob\Roaming`, `D:\Redirected\bob\Roaming`, false},
		{`\\files\home\%USERNAME%\AppData\Roaming`, "", true},
		{`\\?\D:\Redirected\alice`, "", true},
		{`%HOMEDRIVE%\Redirected\alice`, "", true},
		{`Redirected\alice`, "", true},
		{"", "", false},
	} {
		folder, refused := RedirectedAppDataFolder(tc.value, home, `CORP\alice`, `AppData\Roaming`)
		if folder != tc.folder || (refused != "") != tc.refused {
			t.Errorf("RedirectedAppDataFolder(%q) = %q, %q; want %q, refused=%v", tc.value, folder, refused, tc.folder, tc.refused)
		}
	}
}

// A value the account writes cannot crash or stall the enumerator, or leave
// the drive: characters that change length when upper-cased, a name that
// holds a variable, and ".." above the drive root.
func TestRedirectedAppDataFolderOddValues(t *testing.T) {
	const home = `C:\Users\alice`
	for _, tc := range []struct{ value, user string }{
		{"\u0250\u0250%USERPROFILE%\\AppData", `CORP\alice`},
		{"D:\\\u0250\u0250\\%username%\\Roaming\u0250", `CORP\alice`},
		{`D:\Redirected\%USERNAME%\Roaming`, `CORP\a%USERNAME%`},
		{`D:\..\..\Windows`, `CORP\alice`},
	} {
		done := make(chan struct{})
		var folder, refused string
		go func() {
			defer close(done)
			folder, refused = RedirectedAppDataFolder(tc.value, home, tc.user, `AppData\Roaming`)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("RedirectedAppDataFolder(%q, user %q) did not return", tc.value, tc.user)
		}
		if folder != "" && (len(folder) < 3 || folder[1] != ':' || folder[2] != '\\' || strings.Contains(folder, "%")) {
			t.Errorf("RedirectedAppDataFolder(%q, user %q) = %q, %q: not an absolute local folder", tc.value, tc.user, folder, refused)
		}
	}
	if folder, _ := RedirectedAppDataFolder("D:\\\u0250\\%username%\\Roaming", home, `CORP\alice`, `AppData\Roaming`); folder != "D:\\\u0250\\alice\\Roaming" {
		t.Errorf("expanded %q", folder)
	}
	if folder, refused := RedirectedAppDataFolder(`D:\..\..\Windows`, home, `CORP\alice`, `AppData\Roaming`); folder != "" || refused == "" {
		t.Errorf(`D:\..\..\Windows = %q, %q; want refused`, folder, refused)
	}
}
