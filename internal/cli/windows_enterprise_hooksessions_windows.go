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
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The gateway's protected foreign-hook session records (GAP-0352) live in
// %ProgramData%\Cisco\DefenseClaw-HookSessions. This lifecycle step owns
// the folder: install, upgrade, repair and ensure create it (or put its
// owner and access list back), uninstall removes it, and status and verify
// report a missing or untrusted folder. The gateway service creates one
// folder per account in it, with a protected DACL that lets only that
// account read it; a guarded connector's hook reads its own account's
// record during a gateway outage under fail mode open, and blocks when the
// record is missing or untrusted.

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

// ensureWindowsHookSessionRoot makes root a folder this lifecycle created
// with the protected DACL. A folder an unprivileged account created first
// (ProgramData lets users create folders) is removed and created again: its
// owner keeps WRITE_DAC over it.
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
			if err := removeWindowsHookSessionRoot(); err != nil {
				return fmt.Errorf("replace %s, which an unprivileged account created: %w", root, err)
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
	return nil
}

func removeWindowsHookSessionRoot() error {
	root, err := windowsHookSessionDir()
	if err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real folder", root)
	}
	if !strings.EqualFold(filepath.Base(root), windowsHookSessionFolderName) {
		return fmt.Errorf("refusing to remove %s", root)
	}
	return os.RemoveAll(root)
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
		err = managed.ValidateTrustedServiceRuntimeDir(root, "protected foreign-hook session records", windowsHookSessionGatewayAccount)
	}
	if err != nil {
		return root + ": " + err.Error() + ". Every guarded connector's hook refuses its session record and blocks during a gateway outage." +
			" Fix: run " + windowsEnterpriseAdminCommand("repair") + ", which writes the folder's owner and permissions back"
	}
	return ""
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
