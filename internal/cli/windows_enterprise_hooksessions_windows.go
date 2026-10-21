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
// They also hold the records from their start until the folder has been
// replaced and bumped (enterprisepolicy.HoldPublishedSessionRecords: the
// file DefenseClaw-HookSessions.hold next to the folder, in the Cisco folder
// no standard user can change). While the hold is there the hook allows
// nothing during an outage. An account that kept a handle with WRITE_DAC on
// the folder can make it look trusted again and put an older generation
// file and its allows back, and a run that cannot replace the folder (the
// handle refuses the move) or cannot give it an owner the hook refuses (no
// SeRestorePrivilege) has nothing in the folder to stop that; so a run that
// fails before the folder was replaced leaves the hold, and status and
// verify report it, until a later run replaces the folder (GAP-0352, 1.0.4
// review loop round 4).

var (
	windowsHookSessionDir = func() (string, error) {
		layout, err := managed.StandaloneWindowsLayout()
		return layout.HookSessionDir, err
	}
	windowsHookSessionGatewayAccount = `NT SERVICE\` + managed.StandaloneWindowsGatewaySvc
)

// windowsHookSessionFolderName is the folder's last element, which
// uninstall checks before it removes anything.
const windowsHookSessionFolderName = "DefenseClaw-HookSessions"

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
// cannot give it windowsHookSessionRetiredSDDL: no entry for standard users,
// so the hook cannot read the folder's access list and refuses every record
// in it. Its owner is Administrators, so an account whose retained handle
// writes a trusted DACL back makes the folder look trusted again: only the
// hold, which stays when the folder cannot then be moved aside, keeps the
// hook from trusting what the account puts back.
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

// bumpWindowsHookSessionGeneration holds the records and bumps the record
// generation of an existing record folder before an install, upgrade,
// repair or ensure changes anything (GAP-0352): no record written before
// the action proves anything once it started, and the hook allows nothing
// during an outage until ensureWindowsHookSessionRoot has replaced the
// folder, bumped it again and removed the hold. Best effort.
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
	if _, err := os.Lstat(root); err != nil {
		return
	}
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
// aside when an account other than Administrators or SYSTEM owns it: its
// owner keeps WRITE_DAC over it) and a new, empty one is created; the
// gateway creates new record folders in it. When the folder cannot be moved
// (a handle that does not share delete access), it keeps the retired owner,
// which the hook refuses, and the step fails, so the next repair or ensure
// tries again.
//
// The records are held from the start of the step
// (enterprisepolicy.HoldPublishedSessionRecords), and the hold is removed
// only once the new folder was bumped: a step that fails leaves it, so the
// hook allows nothing during an outage even when the folder could get no
// owner the hook refuses (a lifecycle without SeRestorePrivilege) and a
// retained handle then wrote a trusted DACL back.
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
			if err := moveWindowsHookSessionRootAside(root); err != nil {
				return fmt.Errorf("replace %s, which an account other than Administrators or SYSTEM owns: %w", root, err)
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
// use for good. It first gets windowsHookSessionRetiredSDDL, so the hook
// refuses it whatever a handle that kept WRITE_DAC does to its DACL (without
// SeRestorePrivilege it is closed to standard users instead), then it is
// moved aside, where the hook never reads it, and removed. The caller
// creates a new root.
func retireWindowsHookSessionRoot(root string, gateway *windows.SID) error {
	retireErr := windowsHookSessionOwnerRestorePrivilege(func() error { return applyWindowsSDDL(root, windowsHookSessionRetiredSDDL) })
	if retireErr != nil {
		if err := applyWindowsSDDL(root, windowsHookSessionClosedSDDL(gateway)); err != nil {
			return fmt.Errorf("give it an owner the hook refuses: %v; close it: %w", retireErr, err)
		}
	}
	if err := moveWindowsHookSessionRootAside(root); err != nil {
		if retireErr != nil {
			return fmt.Errorf("%w; it is closed to standard users, but it could not get an owner the hook refuses either (%v)", err, retireErr)
		}
		return fmt.Errorf("%w; it keeps an owner the hook refuses", err)
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
		return errors.Join(removeWindowsRetiredHookSessionRoots(root), enterprisepolicy.ReleasePublishedSessionRecords(root))
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real folder", root)
	}
	return errors.Join(os.RemoveAll(root), removeWindowsRetiredHookSessionRoots(root), enterprisepolicy.ReleasePublishedSessionRecords(root))
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
	if enterprisepolicy.PublishedSessionHeld(root) {
		hold, _ := enterprisepolicy.PublishedSessionHoldPath(root)
		return root + " is held (" + hold + "): a DefenseClaw lifecycle run did not finish replacing it, so a guarded connector's hook" +
			" blocks during a gateway outage even when the fail mode is open." +
			" Fix: close any program that keeps a file in the folder open, then run " + windowsEnterpriseAdminCommand("repair") +
			", which replaces the folder and removes the hold"
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
