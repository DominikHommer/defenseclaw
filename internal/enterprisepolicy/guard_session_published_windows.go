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
	"path/filepath"
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
// per-account DACL. A folder this process does not own is replaced. A root
// that Administrators, SYSTEM or this gateway do not own is refused.
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
	if !publishedSessionOwnedByTrusted(root, service) {
		return fmt.Errorf("protected session record root %s is not owned by Administrators, SYSTEM or the gateway", root)
	}
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

// ValidatePublishedSessionPath checks a protected session record, or the
// record folder's key file, before the hook reads it: the file and every
// folder above it are on a fixed NTFS drive, no reparse point, and no
// account but SYSTEM, Administrators, TrustedInstaller and the gateway
// service can write them. Every verdict is fatal, the shared Cisco folder
// included, and the folders DefenseClaw creates with a protected DACL (the
// account's folder and the record root above a record) get the file's own
// strict mask. The key file must be one SYSTEM or Administrators own
// (publishedSessionKeyOwnerCheck). A file the check refuses blocks.
func ValidatePublishedSessionPath(path string, trust PublishedSessionTrust) error {
	if IsPublishedSessionKeyName(filepath.Base(path)) {
		if err := managed.ValidateStrictServiceRuntimeFilePath(path, "protected foreign-hook session record key", trust.ServiceAccount, 0); err != nil {
			return err
		}
		owned, err := publishedSessionKeyOwnerCheck(path)
		if err != nil {
			return err
		}
		if !owned {
			return fmt.Errorf("%s is not a key file SYSTEM or Administrators made", path)
		}
		return nil
	}
	return managed.ValidateStrictServiceRuntimeFilePath(path, "protected foreign-hook session record", trust.ServiceAccount, publishedSessionNamedDirs)
}

// ValidatePublishedSessionRoot checks the record folder root and every
// folder above it the way the hook checks the folders above a record: the
// root strict, every folder above it with the narrow fatal rule, the shared
// Cisco folder included. Status and verify report a root it refuses.
func ValidatePublishedSessionRoot(root string, trust PublishedSessionTrust) error {
	return managed.ValidateStrictServiceRuntimeDirPath(root, "protected foreign-hook session record folder", trust.ServiceAccount, 0)
}

// publishedSessionNamedDirs are the folders above a record that DefenseClaw
// creates with a protected DACL: the account's folder and the record root.
const publishedSessionNamedDirs = 2

// publishedSessionKeySDDL is the protected DACL of a key file: SYSTEM and
// Administrators full control; the gateway service DELETE plus its
// attributes and security descriptor (it removes the key, never writes
// one); standard users the attributes and security descriptor only
// (FILE_READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE), so the hook can check
// who made it while no standard user can open it with an access that a
// sharing mode applies to, or rename or delete it.
func publishedSessionKeySDDL(gateway *windows.SID) string {
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x130080;;;" + gateway.String() + ")(A;;0x120080;;;BU)"
}

// createPublishedSessionKeyFile creates the key file at path, which must
// not exist, with publishedSessionKeySDDL for the gateway service account
// trust names, and flushes it. This process (SYSTEM or an administrator)
// owns it.
func createPublishedSessionKeyFile(path string, trust PublishedSessionTrust) error {
	gateway, err := managed.WindowsServiceAccountSID(trust.ServiceAccount)
	if err == nil && gateway == nil {
		err = errors.New("no gateway service account is named")
	}
	if err != nil {
		return fmt.Errorf("the gateway service account %q: %w", trust.ServiceAccount, err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(publishedSessionKeySDDL(gateway))
	if err != nil {
		return err
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, attributes,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fs.ErrExist
		}
		return err
	}
	return errors.Join(windows.FlushFileBuffers(handle), windows.CloseHandle(handle))
}

// publishedSessionKeyOwnerCheck reports a key file SYSTEM or
// Administrators own: a file (no folder, no reparse point, one link), read
// by handle without following a reparse point. A file this account may not
// open for its security descriptor (every key file lets it) or that is gone
// is not a key.
func publishedSessionKeyOwnerCheck(path string) (bool, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return false, err
	}
	handle, err := windows.CreateFile(pointer, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return false, nil
		}
		return false, err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return false, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		return false, nil
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return false, fmt.Errorf("%s has no owner", path)
	}
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid), nil
}

// publishedSessionSyncDir has nothing to do on Windows: NTFS commits a
// file's creation and deletion in its journal, and the key file itself is
// flushed when it is created.
func publishedSessionSyncDir(string) error { return nil }
