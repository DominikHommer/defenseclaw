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
// the folder: install, upgrade, repair and ensure create it (or put its
// owner and access list back) and bump its record generation, uninstall
// removes it, and status and verify report a missing or untrusted folder or
// generation file. The gateway service creates one folder per account in
// it, with a protected DACL that lets only that account read it; a guarded
// connector's hook reads its own account's record during a gateway outage
// under fail mode open, and blocks when the record is missing, untrusted or
// of an earlier generation. Install, upgrade, repair and ensure bump the
// generation when they start too (bumpWindowsHookSessionGeneration).

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
// in it.
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

// bumpWindowsHookSessionGeneration bumps the record generation of an
// existing record folder before an install, upgrade, repair or ensure
// changes anything (GAP-0352): no record written before the action proves
// anything once it started. ensureWindowsHookSessionRoot bumps again at the
// end. Best effort: a folder that is missing or refused is replaced there.
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
	if _, err := os.Lstat(root); err != nil {
		return
	}
	_ = enterprisepolicy.BumpPublishedSessionGeneration(root)
}

// ensureWindowsHookSessionRoot makes root a folder this lifecycle created
// with the protected DACL, and then bumps its record generation
// (enterprisepolicy.BumpPublishedSessionGeneration): no record written
// before, whatever another account could do to the folder while it was
// loosened, proves anything after it. A folder an unprivileged account
// created first (ProgramData lets users create folders) is moved aside and
// created again: its owner keeps WRITE_DAC over it.
//
// A folder the hook refuses (enterprisepolicy.ValidatePublishedSessionRoot)
// is not put back in place either: an account that opened it with WRITE_DAC
// while it could keeps that access through its handle (GAP-0352 review
// loop round 4), so it could loosen the folder again after the repair and
// swap record folders written after the bump. So the folder object itself
// is retired (retireWindowsHookSessionRoot) and a new, empty one is created.
// When the folder cannot be moved (a handle that does not share delete
// access), it keeps the retired owner, which the hook refuses, and the step
// fails, so the next repair tries again.
func ensureWindowsHookSessionRoot(root string, gateway *windows.SID) error {
	info, err := os.Lstat(root)
	if err == nil {
		if !info.IsDir() || winpath.RejectReparseChain(root) != nil {
			return fmt.Errorf("%s is not a real folder", root)
		}
		trusted, ownerErr := windowsPathOwnedByAdministrators(root)
		if ownerErr != nil {
			return fmt.Errorf("read the owner of %s: %w", root, ownerErr)
		}
		if !trusted {
			if err := moveWindowsHookSessionRootAside(root); err != nil {
				return fmt.Errorf("replace %s, which an account other than Administrators or SYSTEM owns: %w", root, err)
			}
			err = os.ErrNotExist
		} else if problem := windowsHookSessionRootTrustProblem(root); problem != nil {
			if err := retireWindowsHookSessionRoot(root, gateway); err != nil {
				return fmt.Errorf("replace %s, which another account could change (%v): %w", root, problem, err)
			}
			err = os.ErrNotExist
		}
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
	if err := enterprisepolicy.BumpPublishedSessionGeneration(root); err != nil {
		return fmt.Errorf("start a new record generation in %s: %w", root, err)
	}
	// Earlier retired roots: best effort, the hook never reads them.
	_ = removeWindowsRetiredHookSessionRoots(root)
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
		return fmt.Errorf("%w; it keeps an owner the hook refuses, so guarded calls block during an outage until a repair can replace it", err)
	}
	return nil
}

// moveWindowsHookSessionRootAside renames root to a retired name next to it
// (windowsHookSessionRetiredInfix) and removes what it can of it. A handle
// opened without FILE_SHARE_DELETE refuses the rename.
func moveWindowsHookSessionRootAside(root string) error {
	retired := root + windowsHookSessionRetiredInfix + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := os.Rename(root, retired); err != nil {
		return fmt.Errorf("move it aside: %w", err)
	}
	_ = os.RemoveAll(retired)
	return nil
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
		return removeWindowsRetiredHookSessionRoots(root)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real folder", root)
	}
	return errors.Join(os.RemoveAll(root), removeWindowsRetiredHookSessionRoots(root))
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
			" then run " + windowsEnterpriseAdminCommand("repair") + ", which replaces the folder or writes its owner and permissions back, and starts a new record generation"
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
