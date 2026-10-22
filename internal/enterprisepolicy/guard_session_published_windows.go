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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
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
// that Administrators, SYSTEM or this gateway do not own is refused: its
// owner could move a record folder away and put it back after a
// revocation.
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
// record folder's generation file, before the hook reads it: the file and
// every folder above it are on a fixed NTFS drive, no reparse point, and no
// account but SYSTEM, Administrators, TrustedInstaller and the gateway
// service can write them. Every verdict is fatal, the shared Cisco folder
// included, and the folders DefenseClaw creates with a protected DACL (the
// account's folder and the record root above a record, the record root
// above the generation file) get the file's own strict mask. The generation
// file must be owned by SYSTEM or Administrators: only the SYSTEM lifecycle
// and guardian bump it. A file the check refuses blocks.
func ValidatePublishedSessionPath(path string, trust PublishedSessionTrust) error {
	if filepath.Base(path) == PublishedSessionGenerationFile {
		if err := managed.ValidateStrictServiceRuntimeFilePath(path, "protected foreign-hook session record generation", trust.ServiceAccount, 1); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		return checkPublishedSessionGenerationOwner(path, info, false)
	}
	return managed.ValidateStrictServiceRuntimeFilePath(path, "protected foreign-hook session record", trust.ServiceAccount, publishedSessionNamedDirs)
}

// ValidatePublishedSessionRoot checks the record folder root and every
// folder above it the way the hook checks the folders above a record: the
// root strict, every folder above it with the narrow fatal rule, the shared
// Cisco folder included. The Windows lifecycle replaces a root it refuses
// (another account may keep a handle that can change its access list), and
// status and verify report it.
func ValidatePublishedSessionRoot(root string, trust PublishedSessionTrust) error {
	return managed.ValidateStrictServiceRuntimeDirPath(root, "protected foreign-hook session record folder", trust.ServiceAccount, 0)
}

// publishedSessionNamedDirs are the folders above a record that DefenseClaw
// creates with a protected DACL: the account's folder and the record root.
const publishedSessionNamedDirs = 2

// publishedSessionHoldSDDL is the protected DACL of a hold file: SYSTEM
// and Administrators only. No standard user can open it to read or write,
// so none can hold it open without delete sharing and keep the lifecycle
// from removing it; the hook only checks that it is there, which listing
// the hold folder allows.
const publishedSessionHoldSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// publishedSessionHoldDir is the hold folder of the record folder root
// (PublishedSessionHoldDir): the hook runtime folder next to it
// (managed.StandaloneLayout.HookRuntimeDir), to which only SYSTEM and
// Administrators can add a file. Not the Cisco folder above root, where a
// stock ProgramData access list lets standard users create files.
func publishedSessionHoldDir(root string) string {
	return filepath.Join(filepath.Dir(root), managed.StandaloneWindowsHookRuntimeDirName)
}

// publishedSessionHoldReadAccess is FILE_GENERIC_READ | FILE_GENERIC_EXECUTE:
// the most a trusted hold grants anyone but SYSTEM, Administrators and this
// process's account.
const publishedSessionHoldReadAccess = 0x1200a9

// publishedSessionHoldTrusted reports a hold this lifecycle or guardian made:
// a file (no folder, no reparse point, one link) owned by SYSTEM,
// Administrators or this process's account, whose DACL gives no one else
// more than read access. Read by handle, without following a reparse point.
func publishedSessionHoldTrusted(path string) bool {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(pointer, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.Equals(user.User.Sid))
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	if owner, _, err := descriptor.Owner(); err != nil || !trusted(owner) {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil || ace == nil {
			return false
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			// An object or callback entry may grant what this check
			// cannot weigh.
			return false
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)); !trusted(sid) && uint32(ace.Mask)&^publishedSessionHoldReadAccess != 0 {
			return false
		}
	}
	return true
}

// createPublishedSessionHold creates the hold file at path with text and
// publishedSessionHoldSDDL.
func createPublishedSessionHold(path, text string) error {
	return createPublishedSessionMarker(path, publishedSessionHoldSDDL, text)
}

// publishedSessionRefusalInfix follows the record folder's name in the name
// of a refusal (RefusePublishedSessionRoot): <name>.refused-<random>.
const publishedSessionRefusalInfix = ".refused-"

// publishedSessionRefusalSDDL is the protected DACL of a refusal: SYSTEM and
// Administrators full control, standard users its attributes and security
// descriptor only (FILE_READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE), so the
// hook can check who made it (publishedSessionHoldTrusted) while no standard
// user can open it with an access that a sharing mode applies to, and none
// can keep the lifecycle from removing it.
const publishedSessionRefusalSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120080;;;BU)"

// publishedSessionRefusalPlace is the folder of the refusals of the record
// folder root (the folder above it, %ProgramData%\Cisco) and the prefix of
// their names.
func publishedSessionRefusalPlace(root string) (dir, prefix string, ok bool) {
	root = strings.TrimRight(strings.TrimSpace(root), `\/`)
	if root == "" || !filepath.IsAbs(root) {
		return "", "", false
	}
	root = filepath.Clean(root)
	if root == filepath.Dir(root) {
		return "", "", false
	}
	return filepath.Dir(root), filepath.Base(root) + publishedSessionRefusalInfix, true
}

// RefusePublishedSessionRoot makes the hook refuse the record folder root
// until a lifecycle run replaced it (ReleasePublishedSessionRecords), with
// a file next to the folder, in %ProgramData%\Cisco, that SYSTEM or
// Administrators own (GAP-0352, 1.0.4 guard loop round 3). It is for a
// lifecycle that can give a folder it cannot replace no owner the hook
// refuses: SYSTEM without SeRestorePrivilege may name only itself or
// Administrators as an owner, and the hook trusts both, so an account that
// kept a handle with WRITE_DAC on the folder could make it look trusted
// again, and one that also kept a handle on the hook runtime folder could
// delete the hold there. No handle on either folder reaches this file, and
// no standard user may delete a file another account made in
// %ProgramData%\Cisco. Its name ends in random characters, so no account
// can put its own file at the path first and keep the lifecycle from
// making it; a file a standard user made with the prefix is ignored. A
// trusted refusal already in place is kept.
func RefusePublishedSessionRoot(root string) error {
	dir, prefix, ok := publishedSessionRefusalPlace(root)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	if refusals, err := publishedSessionRootRefusals(root); err == nil && len(refusals) != 0 {
		return nil
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	return createPublishedSessionMarker(filepath.Join(dir, prefix+hex.EncodeToString(nonce[:])), publishedSessionRefusalSDDL, publishedSessionHoldText)
}

// publishedSessionRootRefusals lists the refusals of the record folder root
// in place: files with the refusal prefix next to the folder that SYSTEM,
// Administrators or this process's account made, and that no one else may
// change (publishedSessionHoldTrusted). A folder above root that cannot be
// listed is an error, which holds the records.
func publishedSessionRootRefusals(root string) ([]string, error) {
	dir, prefix, ok := publishedSessionRefusalPlace(root)
	if !ok {
		return nil, fmt.Errorf("no protected session record folder %q", root)
	}
	names, err := publishedSessionHoldList(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var refusals []string
	for _, name := range names {
		if path := filepath.Join(dir, name); hasPrefixFold(name, prefix) && publishedSessionHoldTrusted(path) {
			refusals = append(refusals, path)
		}
	}
	return refusals, nil
}

// releasePublishedSessionRootRefusals removes the refusals of the record
// folder root, once a lifecycle run replaced the folder and bumped it.
func releasePublishedSessionRootRefusals(root string) error {
	refusals, err := publishedSessionRootRefusals(root)
	if err != nil {
		return err
	}
	var errs []error
	for _, path := range refusals {
		errs = append(errs, releasePublishedSessionAt(path))
	}
	return errors.Join(errs...)
}

// createPublishedSessionMarker creates the file at path, which must not
// exist, with text and the protected DACL sddl, owned by this process's
// account (SYSTEM or an administrator).
func createPublishedSessionMarker(path, sddl, text string) error {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
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
	var written uint32
	_ = windows.WriteFile(handle, []byte(text), &written, nil)
	return windows.CloseHandle(handle)
}

// publishedSessionGenerationSDDL is the protected DACL of the generation
// file: SYSTEM and Administrators full control, standard users and services
// (the gateway) read. It inherits nothing from the record root, which gives
// the gateway modify.
const publishedSessionGenerationSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;SU)"

// createPublishedSessionGeneration creates the generation file at path with
// publishedSessionGenerationSDDL; this process (SYSTEM or an administrator)
// owns it.
func createPublishedSessionGeneration(path string) error {
	descriptor, err := windows.SecurityDescriptorFromString(publishedSessionGenerationSDDL)
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
	return windows.CloseHandle(handle)
}

// checkPublishedSessionGenerationOwner checks that SYSTEM or Administrators own
// the generation file, for the gateway, the hook and the bump alike.
func checkPublishedSessionGenerationOwner(path string, _ os.FileInfo, _ bool) error {
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s has no owner", path)
	}
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return fmt.Errorf("%s is owned by %s, not SYSTEM or Administrators", path, owner.String())
	}
	return nil
}

// expirePublishedSessionRecord sets the modification time of the record at
// path to publishedSessionRevokedTime (revokePublishedSessionRecord).
func expirePublishedSessionRecord(path string) error {
	return publishedSessionSetTime(path, publishedSessionRevokedTime)
}

// setPublishedSessionTime sets the access and modification time of the
// file at path. It opens the file for its attributes only, which no sharing
// mode of a reader refuses, and without following a reparse point.
func setPublishedSessionTime(path string, at time.Time) error {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(pointer, windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return fs.ErrNotExist
		}
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	stamp := windows.NsecToFiletime(at.UnixNano())
	return windows.SetFileTime(handle, nil, &stamp, &stamp)
}

// publishedSessionPendingTime is the creation time that is the guardian's
// pending mark on an account's private session store
// (MarkForeignHookRemovalPending). The gateway's writes do not change a
// folder's creation time, no standard user can reach the store, and setting
// it needs no free space.
var publishedSessionPendingTime = time.Unix(1, 0).UTC()

// publishedSessionPendingFlag reports the pending mark.
func publishedSessionPendingFlag(info os.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.CreationTime.Nanoseconds() == publishedSessionPendingTime.UnixNano()
}

// publishedSessionSetPending sets the pending mark of dir, or clears it (the
// creation time becomes now), through an attributes-only handle that does
// not follow a reparse point.
func publishedSessionSetPending(dir string, on bool) error {
	pointer, err := winpath.UTF16Ptr(dir)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(pointer, windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	created := time.Now()
	if on {
		created = publishedSessionPendingTime
	}
	stamp := windows.NsecToFiletime(created.UnixNano())
	return windows.SetFileTime(handle, &stamp, nil, nil)
}

// publishedSessionCreatePendingDir creates the private session store the
// guardian marks for an account that has none, and the store folder above
// it. Both inherit the data directory's access list, so the gateway can use
// the store once the mark is cleared.
func publishedSessionCreatePendingDir(_, dir string) error {
	return os.MkdirAll(dir, 0o700)
}
