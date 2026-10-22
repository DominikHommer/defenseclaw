// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"golang.org/x/sys/windows"
)

// processRunsAsCaller reports whether the user SID of pid's process token is
// this process's. Another account's process denies TOKEN_QUERY to a
// standard user, which is an error, never a match.
func processRunsAsCaller(pid int) error {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	owner, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if !owner.User.Sid.Equals(self.User.Sid) {
		return errProcessOfAnotherAccount
	}
	return nil
}
