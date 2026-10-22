// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The gateway's protected foreign-hook session records (GAP-0352) live in
// %ProgramData%\Cisco\DefenseClaw-HookSessions. This lifecycle step owns
// the folder: install, upgrade, repair and ensure replace it with a new one
// and bump its record generation, uninstall
// removes it, and status and verify report a missing or untrusted folder or
// generation file. The gateway service creates one folder per account in
// it, with a protected DACL that lets only that account read it; a guarded
// connector's hook reads its own account's record during a gateway outage
// under fail mode open, and blocks when the record is missing, untrusted or
// of an earlier generation. Install, upgrade, repair and ensure bump the
// generation when they start too (bumpWindowsHookSessionGeneration).
//
// From their start until the folder has been replaced and bumped they also
// keep the folder refused and held. An account that kept a handle with
// WRITE_DAC on the folder can make its access list look trusted again and
// put an older generation file and its allows back, so the folder is given
// an owner the hook refuses, which no such handle can change
// (refuseWindowsHookSessionRoot: LOCAL SERVICE, or without
// SeRestorePrivilege the lifecycle's own account), and a run that fails
// before the folder was replaced leaves it refused. The hold
// (enterprisepolicy.HoldPublishedSessionRecords: the file
// DefenseClaw-HookSessions.hold in the hook runtime folder, to which no
// standard user can add a file) is kept as well, and status and verify
// report it, but the hook no longer depends on it alone: an account that
// also kept a handle on the hook runtime folder could delete it (GAP-0352,
// 1.0.4 review loop round 4, guard loop round 2). A lifecycle that can
// give the folder neither owner (SYSTEM without SeRestorePrivilege) refuses
// it with a file next to it in %ProgramData%\Cisco instead, which no such
// handle reaches (guard loop round 3).

var (
	windowsHookSessionDir = func() (string, error) {
		layout, err := managed.StandaloneWindowsLayout()
		return layout.HookSessionDir, err
	}
	windowsHookSessionGatewayAccount = `NT SERVICE\` + managed.StandaloneWindowsGatewaySvc
)

// windowsHookSessionFolderName is the folder's last element, which
// uninstall checks before it removes anything.
const windowsHookSessionFolderName = managed.StandaloneWindowsHookSessionDirName

// windowsHookSessionDACL: LocalSystem and Administrators full control, the
// gateway service modify (it creates and replaces the per-account folders),
// standard users read and list of this folder only (they reach their own
// folder through its own DACL, and the hook checks the DACL of every folder
// above a record). No other access.
func windowsHookSessionDACL(gateway *windows.SID) string {
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)(A;OICI;0x1301bf;;;" + gateway.String() + ")"
}

func windowsHookSessionSDDL(gateway *windows.SID) string {
	return "O:BAG:SY" + windowsHookSessionDACL(gateway)
}

// windowsHookSessionClosedSDDL closes a folder the lifecycle retires when it
// can give it no owner the hook refuses (refuseWindowsHookSessionRoot): no
// entry for standard users, so the hook cannot read the folder's access
// list and refuses every record in it. Its owner is Administrators, so an
// account whose retained handle writes a trusted DACL back makes the
// folder look trusted again: only the hold, which stays when the folder
// cannot then be moved aside, keeps the hook from trusting what the account
// puts back. Only a lifecycle that runs as SYSTEM without
// SeRestorePrivilege gets here.
func windowsHookSessionClosedSDDL(gateway *windows.SID) string {
	return "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;" + gateway.String() + ")"
}

// windowsHookSessionRetiredSDDL is a record root the lifecycle retires: owned
// by LOCAL SERVICE, which neither the hook nor this lifecycle trusts as an
// owner (windowsPathOwnedByAdministrators), and which no standard user can
// put back (an owner other than oneself needs SeRestorePrivilege), so an
// account that holds a handle with WRITE_DAC on the folder cannot make the
// hook trust it again; no entry for standard users or the gateway.
const windowsHookSessionRetiredSDDL = "O:LSG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// windowsHookSessionSelfOwnedSDDL is windowsHookSessionRetiredSDDL for a
// lifecycle without SeRestorePrivilege: owned by the account the lifecycle
// runs as (an elevated administrator's own account, which a caller may
// always make the owner without a privilege, and which the hook refuses as
// an owner), with the same entries.
func windowsHookSessionSelfOwnedSDDL(self *windows.SID) string {
	return "O:" + self.String() + "G:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
}

// windowsHookSessionLifecycleAccount is the account this lifecycle runs as
// (replaceable in tests).
var windowsHookSessionLifecycleAccount = func() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

// windowsHookSessionOwnerRefused reports an owner the hook refuses for the
// record root and the folders above a record, and the lifecycle does not
// trust either (windowsPathOwnedByAdministrators): not SYSTEM,
// Administrators or TrustedInstaller (managed.IsWindowsTrustedAdminOwner),
// and not the gateway service, which the hook accepts as an owner.
func windowsHookSessionOwnerRefused(sid *windows.SID) bool {
	if sid == nil || managed.IsWindowsTrustedAdminOwner(sid) {
		return false
	}
	gateway, err := managed.WindowsServiceAccountSID(windowsHookSessionGatewayAccount)
	return err == nil && gateway != nil && !sid.Equals(gateway)
}

// refuseWindowsHookSessionRoot gives the record root at root an owner the
// hook refuses and that no handle an account kept can change (an owner
// change needs WRITE_OWNER, and naming another account needs
// SeRestorePrivilege), with no entry for standard users or the gateway:
// LOCAL SERVICE (windowsHookSessionRetiredSDDL, with SeRestorePrivilege),
// or else the account this lifecycle runs as when the hook refuses it as
// an owner (windowsHookSessionSelfOwnedSDDL: an elevated administrator
// whose token lacks the privilege). Whatever DACL a handle that kept
// WRITE_DAC writes back afterwards, the hook refuses the folder until a
// later run replaces it (GAP-0352, 1.0.4 guard loop round 2: without the
// privilege the folder used to keep an Administrators owner, so a handle
// that also reached the hook runtime folder could delete the hold, write a
// trusted DACL back and put the old tree back).
//
// A lifecycle that can give it neither owner (SYSTEM without
// SeRestorePrivilege may name only itself or Administrators, and the hook
// trusts both) refuses it next to the folder instead
// (enterprisepolicy.RefusePublishedSessionRoot: a file in
// %ProgramData%\Cisco that no handle on the record folder or on the hook
// runtime folder reaches), which the hook honors until a run replaced the
// folder (1.0.4 guard loop round 3: the folder used to keep its
// Administrators owner with only the hold as its guard). An error means
// none of the three took.
func refuseWindowsHookSessionRoot(root string) error {
	retireErr := windowsHookSessionOwnerRestorePrivilege(func() error { return applyWindowsSDDL(root, windowsHookSessionRetiredSDDL) })
	if retireErr == nil {
		return nil
	}
	ownerErr := fmt.Errorf("give it the LOCAL SERVICE owner: %v", retireErr)
	self, err := windowsHookSessionLifecycleAccount()
	switch {
	case err != nil:
		ownerErr = fmt.Errorf("%w; read this lifecycle's account: %v", ownerErr, err)
	case !windowsHookSessionOwnerRefused(self):
		ownerErr = fmt.Errorf("%w; this lifecycle runs as %s, an owner the hook trusts", ownerErr, self.String())
	default:
		err = applyWindowsSDDL(root, windowsHookSessionSelfOwnedSDDL(self))
		if err == nil {
			return nil
		}
		ownerErr = fmt.Errorf("%w; give it this lifecycle's own account as its owner: %v", ownerErr, err)
	}
	if err := windowsHookSessionRefuseRoot(root); err != nil {
		return fmt.Errorf("%w; refuse it next to the folder: %v", ownerErr, err)
	}
	return nil
}

// windowsHookSessionRefuseRoot refuses a record root next to it
// (replaceable in tests).
var windowsHookSessionRefuseRoot = enterprisepolicy.RefusePublishedSessionRoot

// windowsHookSessionRetiredInfix names a retired record root next to the
// root: <root>.retired-<nanoseconds>. The hook never reads it.
const windowsHookSessionRetiredInfix = ".retired-"

// windowsHookSessionOwnerRestorePrivilege runs fn with SeRestorePrivilege,
// which setting the retired owner needs (replaceable in tests).
var windowsHookSessionOwnerRestorePrivilege = enterprisehooks.RunWithWindowsAdministratorOwnerRestorePrivilege

// windowsHookSessionRootTrustProblem reports a record folder, or a folder
// above it, that the hook refuses (enterprisepolicy.ValidatePublishedSessionRoot);
// replaceable in tests.
var windowsHookSessionRootTrustProblem = func(root string) error {
	return enterprisepolicy.ValidatePublishedSessionRoot(root, enterprisepolicy.PublishedSessionTrust{ServiceAccount: windowsHookSessionGatewayAccount})
}

// bumpWindowsHookSessionGeneration holds the records, gives an existing
// record folder an owner the hook refuses (refuseWindowsHookSessionRoot)
// and bumps its record generation before an install, upgrade, repair or
// ensure changes anything (GAP-0352): no record written before the action
// proves anything once it started, and the hook allows nothing during an
// outage until ensureWindowsHookSessionRoot has replaced the folder, bumped
// the new one and removed the hold. The refused owner keeps that so while
// the action runs, and after an action that stopped, also against an
// account that kept handles on the folder and on the hook runtime folder
// with the hold (1.0.4 guard loop round 2). Best effort.
func bumpWindowsHookSessionGeneration(action string) {
	switch action {
	case "install", "upgrade", "repair", "ensure":
	default:
		return
	}
	if !windowsEnterpriseIsElevated() {
		return
	}
	root, err := windowsHookSessionDir()
	if err != nil || strings.TrimSpace(root) == "" {
		return
	}
	_ = enterprisepolicy.HoldPublishedSessionRecords(root)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || winpath.RejectReparseChain(root) != nil {
		return
	}
	_ = refuseWindowsHookSessionRoot(root)
	_ = enterprisepolicy.BumpPublishedSessionGeneration(root)
}

// ensureWindowsHookSessionRoot makes root a new folder this lifecycle
// created with the protected DACL, and then bumps its record generation
// (enterprisepolicy.BumpPublishedSessionGenerationPast) past the one of the
// folder it replaced: no record written before, whatever another account
// could do to the folder while it was loosened, proves anything after it.
//
// An existing folder is never kept, even when its owner and access list
// look right (GAP-0352 review loop round 4, and loop round 2 of the 1.0.4
// round): access is checked when a handle is opened, so an account that
// held WRITE_DAC on the root, its own record folder, a record or the
// generation file at any time keeps it through the handle after the DACL is
// put back, and could grant itself write access again after this repair and
// put a fresh allow of the new generation there. So the root folder object
// is retired with everything in it (retireWindowsHookSessionRoot, or moved
// aside when an account other than Administrators or SYSTEM owns it: the
// start of the run gave it a refused owner, or its owner keeps WRITE_DAC
// over it) and a new, empty one is created; the gateway creates new record
// folders in it. When the folder cannot be moved (a handle that does not
// share delete access), it keeps an owner the hook refuses
// (refuseWindowsHookSessionRoot), and the step fails, so the next repair or
// ensure tries again.
//
// The records are held from the start of the step
// (enterprisepolicy.HoldPublishedSessionRecords), and the hold is removed
// only once the new folder was bumped: a step that fails leaves it, as the
// last guard of a lifecycle that could not refuse the folder.
func ensureWindowsHookSessionRoot(root string, gateway *windows.SID) error {
	holdErr := enterprisepolicy.HoldPublishedSessionRecords(root)
	if err := replaceWindowsHookSessionRoot(root, gateway); err != nil {
		if holdErr != nil {
			return fmt.Errorf("%w; the records could not be held either (%v), so run repair again as soon as the folder can be replaced", err, holdErr)
		}
		return fmt.Errorf("%w; the records stay held, so guarded calls block during a gateway outage until a repair replaces the folder", err)
	}
	if err := enterprisepolicy.ReleasePublishedSessionRecords(root); err != nil {
		return fmt.Errorf("remove the hold of %s: %w", root, err)
	}
	// Earlier retired roots: best effort, the hook never reads them.
	_ = removeWindowsRetiredHookSessionRoots(root)
	return nil
}

// replaceWindowsHookSessionRoot is ensureWindowsHookSessionRoot without the
// hold: it retires the folder at root, creates a new one and bumps it.
func replaceWindowsHookSessionRoot(root string, gateway *windows.SID) error {
	var floor time.Time
	info, err := os.Lstat(root)
	if err == nil {
		if !info.IsDir() || winpath.RejectReparseChain(root) != nil {
			return fmt.Errorf("%s is not a real folder", root)
		}
		floor = enterprisepolicy.PublishedSessionGenerationFloor(root)
		trusted, ownerErr := windowsPathOwnedByAdministrators(root)
		if ownerErr != nil {
			return fmt.Errorf("read the owner of %s: %w", root, ownerErr)
		}
		if !trusted {
			// Refused at the start of the run, or owned by another
			// account, which keeps WRITE_DAC over it.
			if err := moveWindowsHookSessionRootAside(root); err != nil {
				return fmt.Errorf("replace %s, which is not owned by Administrators or SYSTEM, so the hook refuses it until it is replaced: %w", root, err)
			}
		} else if err := retireWindowsHookSessionRoot(root, gateway); err != nil {
			if problem := windowsHookSessionRootTrustProblem(root); problem != nil {
				return fmt.Errorf("replace %s, which another account could change (%v): %w", root, problem, err)
			}
			return fmt.Errorf("replace %s, which an account may still hold a handle to: %w", root, err)
		}
		err = os.ErrNotExist
	}
	if errors.Is(err, os.ErrNotExist) {
		descriptor, err := windows.SecurityDescriptorFromString(windowsHookSessionDACL(gateway))
		if err != nil {
			return err
		}
		attributes := &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: descriptor,
		}
		pointer, err := winpath.UTF16Ptr(root)
		if err != nil {
			return err
		}
		if err := windows.CreateDirectory(pointer, attributes); err != nil {
			return fmt.Errorf("create %s: %w", root, err)
		}
	} else if err != nil {
		return err
	}
	if err := applyWindowsSDDL(root, windowsHookSessionSDDL(gateway)); err != nil {
		return fmt.Errorf("protect %s: %w", root, err)
	}
	if err := enterprisepolicy.BumpPublishedSessionGenerationPast(root, floor); err != nil {
		return fmt.Errorf("start a new record generation in %s: %w", root, err)
	}
	return nil
}

// retireWindowsHookSessionRoot takes the record root folder object out of
// use for good. It is first refused (refuseWindowsHookSessionRoot: an owner
// the hook refuses, or a refusal next to it), so the hook refuses it
// whatever a handle that kept WRITE_DAC does to its DACL (a lifecycle that
// can do neither closes it to standard users instead), then it is moved
// aside, where the hook never reads it, and removed. The caller creates a
// new root.
func retireWindowsHookSessionRoot(root string, gateway *windows.SID) error {
	retireErr := refuseWindowsHookSessionRoot(root)
	if retireErr != nil {
		if err := applyWindowsSDDL(root, windowsHookSessionClosedSDDL(gateway)); err != nil {
			return fmt.Errorf("give it an owner the hook refuses: %v; close it: %w", retireErr, err)
		}
	}
	if err := moveWindowsHookSessionRootAside(root); err != nil {
		if retireErr != nil {
			return fmt.Errorf("%w; it is closed to standard users, but it could not get an owner the hook refuses either (%v)", err, retireErr)
		}
		return fmt.Errorf("%w; the hook refuses it until it is replaced", err)
	}
	return nil
}

// windowsHookSessionMoveAttempts and windowsHookSessionMoveRetry bound how
// often a rename that a handle refuses is tried again: a reader that
// closes its handle a moment later (the gateway writing a record, a hook
// reading one) does not fail the step.
const (
	windowsHookSessionMoveAttempts = 3
	windowsHookSessionMoveRetry    = 100 * time.Millisecond
)

// moveWindowsHookSessionRootAside renames root to a retired name next to it
// (windowsHookSessionRetiredInfix) and removes what it can of it. A handle
// opened without FILE_SHARE_DELETE refuses the rename.
func moveWindowsHookSessionRootAside(root string) error {
	var err error
	for attempt := 0; attempt < windowsHookSessionMoveAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(windowsHookSessionMoveRetry)
		}
		retired := root + windowsHookSessionRetiredInfix + strconv.FormatInt(time.Now().UnixNano(), 10)
		if err = os.Rename(root, retired); err == nil {
			_ = os.RemoveAll(retired)
			return nil
		}
	}
	return fmt.Errorf("move it aside: %w", err)
}

// removeWindowsRetiredHookSessionRoots removes the retired roots next to
// root that are still there (a handle kept one open). Only real folders
// whose name is the root's with windowsHookSessionRetiredInfix go.
func removeWindowsRetiredHookSessionRoots(root string) error {
	parent := filepath.Dir(root)
	entries, err := os.ReadDir(parent)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	prefix := strings.ToLower(filepath.Base(root) + windowsHookSessionRetiredInfix)
	var errs []error
	for _, entry := range entries {
		if !strings.HasPrefix(strings.ToLower(entry.Name()), prefix) {
			continue
		}
		path := filepath.Join(parent, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func removeWindowsHookSessionRoot() error {
	root, err := windowsHookSessionDir()
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Base(root), windowsHookSessionFolderName) {
		return fmt.Errorf("refusing to remove %s", root)
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return errors.Join(removeWindowsRetiredHookSessionRoots(root), enterprisepolicy.RemovePublishedSessionHolds(root))
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real folder", root)
	}
	return errors.Join(os.RemoveAll(root), removeWindowsRetiredHookSessionRoots(root), enterprisepolicy.RemovePublishedSessionHolds(root))
}

// windowsHookSessionRootProblem names a missing or untrusted folder, or "".
func windowsHookSessionRootProblem() string {
	root, err := windowsHookSessionDir()
	if err != nil || strings.TrimSpace(root) == "" {
		return ""
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return root + " is missing. It holds the gateway's protected foreign-hook session records; without it a guarded connector " +
			"(Copilot, OpenCode) blocks during a gateway outage even when the fail mode is open." +
			" Fix: run " + windowsEnterpriseAdminCommand("repair")
	}
	if holds, err := enterprisepolicy.PublishedSessionHolds(root); err != nil || len(holds) != 0 {
		named := strings.Join(holds, ", ")
		if err != nil {
			named = "its hold folder cannot be listed: " + err.Error()
		}
		return root + " is held (" + named + "): a DefenseClaw lifecycle run did not finish replacing it, or the hook guardian did not finish" +
			" invalidating it after a hook removal, so a guarded connector's hook blocks during a gateway outage even when the fail mode is open." +
			" Fix: close any program that keeps a file in the folder open, then run " + windowsEnterpriseAdminCommand("repair") +
			", which replaces the folder and removes its hold; the hook guardian removes its own hold at its next pass"
	}
	trusted, err := windowsPathOwnedByAdministrators(root)
	if err == nil && !trusted {
		err = errors.New("it is not owned by Administrators or SYSTEM")
	}
	if err == nil {
		// The hook's own rule (GAP-0352 review): the folder strict, and every
		// folder above it with fatal verdicts, the shared Cisco folder
		// included. The advisory ancestor verdicts of
		// ValidateTrustedServiceRuntimeDir would hide a drifted Cisco folder
		// that makes every hook refuse its record.
		err = windowsHookSessionRootTrustProblem(root)
	}
	if err == nil {
		// The generation file the hook checks every record against.
		err = windowsHookSessionGenerationProblem(root)
	}
	if err != nil {
		return root + ": " + err.Error() + ". A guarded connector's hook refuses the session records there and blocks during a gateway outage." +
			" Fix: if a folder above it lets other accounts change it, put that folder's permissions back," +
			" then run " + windowsEnterpriseAdminCommand("repair") + ", which replaces the folder and starts a new record generation"
	}
	return ""
}

// windowsHookSessionGenerationProblem reports a generation file under root
// that the hook refuses; replaceable in tests.
var windowsHookSessionGenerationProblem = func(root string) error {
	path, ok := enterprisepolicy.PublishedSessionGenerationPath(root)
	if !ok {
		return errors.New("it names no generation file")
	}
	if err := enterprisepolicy.ValidatePublishedSessionPath(path, enterprisepolicy.PublishedSessionTrust{ServiceAccount: windowsHookSessionGatewayAccount}); err != nil {
		return err
	}
	_, err := enterprisepolicy.PublishedSessionGeneration(root)
	return err
}

// applyWindowsStandaloneHookSessionRecords runs the folder's lifecycle step
// at the end of a standalone action.
func applyWindowsStandaloneHookSessionRecords(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) {
	if result == nil || opts == nil || opts.runningDeploymentLabel {
		return
	}
	switch result.Action {
	case "install", "upgrade", "repair", "ensure":
		if len(result.Errors) != 0 {
			return
		}
		root, err := windowsHookSessionDir()
		if err == nil {
			var gateway *windows.SID
			if gateway, err = managed.WindowsServiceAccountSID(windowsHookSessionGatewayAccount); err == nil {
				err = ensureWindowsHookSessionRoot(root, gateway)
			}
		}
		if err != nil {
			result.AddWarning("hook_session_records_unavailable", "the protected foreign-hook session record folder could not be prepared ("+
				err.Error()+"); guarded connectors block during a gateway outage even when the fail mode is open")
		}
	case "uninstall":
		if len(result.Errors) != 0 {
			return
		}
		if err := removeWindowsHookSessionRoot(); err != nil {
			result.AddWarning("hook_session_records_left", "the protected foreign-hook session record folder could not be removed: "+err.Error())
		}
	case "status", "verify":
		if result.Installed && !windowsEnterpriseResultHasWarning(result, windowsEnterpriseHealthNotChecked) {
			if problem := windowsHookSessionRootProblem(); problem != "" {
				result.AddWarning("hook_session_records_untrusted", problem)
			}
		}
	}
}
