// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// WindowsProtectedTargetFromOtherRelease reads, without writing, the
// protected hook-contract lock entry of one managed target and reports the
// DefenseClaw release that wrote it when that is another release than this
// binary. The guardian asks only after the target failed verification while
// its account is signed out: an upgrade renders new hooks that only the
// account's own Windows session can install, so the target waits for that
// account's next sign-in instead of failing the whole upgrade (GAP-0644).
// A lock that cannot be read, or one this release wrote, is not from
// another release; such a failure stays a failure. Both profiles: a Secure
// Client upgrade with a signed-out enrolled account failed the same way.
func WindowsProtectedTargetFromOtherRelease(opts InstallOptions) (string, bool, error) {
	lock, err := windowsProtectedTargetLock(opts)
	if err != nil {
		return "", false, err
	}
	written := strings.TrimSpace(lock.DefenseClawVersion)
	if written == "" || written == strings.TrimSpace(version.Current().BinaryVersion) {
		return "", false, nil
	}
	return written, true, nil
}

// WindowsProtectedTargetRenderedClosedForOpen reports whether one managed
// target's protected hook-contract lock records fail mode closed while opts
// asks for open. An administrator who opens the hook fail mode makes every
// enrolled target fail verification, and a signed-out (or disconnected)
// account cannot be re-rendered until its next sign-in; until then its
// hooks still fail closed, the stricter mode, so the target waits for that
// sign-in instead of failing the whole change (rel-1-0-4 GAP-0585). A change
// to closed is not excused: it would leave a running session fail-open.
func WindowsProtectedTargetRenderedClosedForOpen(opts InstallOptions) (bool, error) {
	if canonicalHookFailMode(opts.HookFailMode) != "open" {
		return false, nil
	}
	lock, err := windowsProtectedTargetLock(opts)
	if err != nil {
		return false, err
	}
	return lock.Connector != "" && canonicalHookFailMode(lock.HookFailMode) == "closed", nil
}

// windowsProtectedTargetLock reads, without writing, the protected
// hook-contract lock entry of one managed target; an entry for another
// connector reads as none.
func windowsProtectedTargetLock(opts InstallOptions) (connector.HookContractLockEntry, error) {
	home, _, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err != nil {
		return connector.HookContractLockEntry{}, err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, opts.DataDir)
	if err != nil {
		return connector.HookContractLockEntry{}, err
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	lock, err := connector.LoadHookContractLockEntryForMode(dataDir, name, true)
	if err != nil || lock.Connector != name {
		return connector.HookContractLockEntry{}, err
	}
	return lock, nil
}

// WindowsSecureClientProfileProcess reports whether this guardian serves the
// Secure Client profile rather than the standalone one.
func WindowsSecureClientProfileProcess() bool {
	return !windowsEnterpriseStandaloneProcess()
}

// IsWindowsEnterpriseNotLocalSystem reports the refusal of a session or
// mutation check run outside LocalSystem, such as Setup's own verify as the
// elevated administrator, which cannot query another account's session.
func IsWindowsEnterpriseNotLocalSystem(err error) bool {
	return errors.Is(err, errWindowsEnterpriseNotLocalSystem)
}
