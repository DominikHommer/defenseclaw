// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "testing"

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
