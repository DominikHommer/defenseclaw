//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// publishedSessionFileMode: a record inherits the per-user folder's DACL.
func publishedSessionFileMode(*os.File) error { return nil }

// publishedSessionUserReadAccess is FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
// (read and list, no write), and publishedSessionServiceAccess is Modify.
const (
	publishedSessionUserReadAccess = "0x1200a9"
	publishedSessionServiceAccess  = "0x1301bf"
)

// publishedSessionDirSDDL is the owner and protected DACL of one account's
// folder: owned by the gateway service (this process's token user, so a
// later publish recognizes its own folder), SYSTEM and Administrators full
// control, the gateway service modify, the account read, all inherited by
// the records.
func publishedSessionDirSDDL(service, account *windows.SID) string {
	return "O:" + service.String() + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;" + publishedSessionServiceAccess + ";;;" + service.String() +
		")(A;OICI;" + publishedSessionUserReadAccess + ";;;" + account.String() + ")"
}

// publishedSessionPrepare makes dir, below the folder the SYSTEM lifecycle
// created (root), a folder this gateway created with the protected
// per-account DACL. A folder this process does not own is replaced.
func publishedSessionPrepare(root, dir, identity string) error {
	if err := publishedSessionRealDir(root); err != nil {
		return fmt.Errorf("protected session record root %s: %w", root, err)
	}
	account, err := windows.StringToSid(identity)
	if err != nil {
		return fmt.Errorf("protected session record: identity %q is not a SID: %w", identity, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	service := user.User.Sid
	for attempt := 0; attempt < 2; attempt++ {
		_, err := os.Lstat(dir)
		if errors.Is(err, fs.ErrNotExist) {
			descriptor, err := windows.SecurityDescriptorFromString(publishedSessionDirSDDL(service, account))
			if err != nil {
				return err
			}
			attributes := &windows.SecurityAttributes{
				Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
				SecurityDescriptor: descriptor,
			}
			pointer, err := winpath.UTF16Ptr(dir)
			if err != nil {
				return err
			}
			if err := windows.CreateDirectory(pointer, attributes); err != nil {
				if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
					continue
				}
				return fmt.Errorf("create %s: %w", dir, err)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if publishedSessionRealDir(dir) == nil && publishedSessionOwnedByTrusted(dir, service) {
			return nil
		}
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	return fmt.Errorf("protected session record folder %s keeps changing", dir)
}

func publishedSessionRealDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !info.IsDir() {
		return fmt.Errorf("%s is not a folder", path)
	}
	return winpath.RejectReparseChain(path)
}

// publishedSessionOwnedByTrusted reports a folder owned by the gateway
// service, Administrators or SYSTEM.
func publishedSessionOwnedByTrusted(path string, service *windows.SID) bool {
	extended, err := winpath.Extended(path)
	if err != nil {
		return false
	}
	descriptor, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	current, _, err := descriptor.Owner()
	return err == nil && current != nil && (current.Equals(service) ||
		current.IsWellKnown(windows.WinBuiltinAdministratorsSid) || current.IsWellKnown(windows.WinLocalSystemSid))
}

// ValidatePublishedSessionPath checks a protected session record before the
// hook reads it: the record and every folder above it are on a fixed NTFS
// drive, no reparse point, and no account but SYSTEM, Administrators,
// TrustedInstaller and the gateway service can write them.
func ValidatePublishedSessionPath(path string, trust PublishedSessionTrust) error {
	return managed.ValidateTrustedServiceRuntimeFilePath(path, "protected foreign-hook session record", trust.ServiceAccount)
}
