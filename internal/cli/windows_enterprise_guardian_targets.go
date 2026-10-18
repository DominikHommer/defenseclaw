// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// windowsEnterpriseGuardianRepairPendingCode is the warning of a target the
// standalone Windows guardian has not verified as protected: its last pass
// failed on it, or one of its hook files is gone since. Linux and macOS use
// the same code for a hook file changed since the guardian's pass.
const windowsEnterpriseGuardianRepairPendingCode = "guardian_repair_pending"

// applyWindowsEnterpriseGuardianTargetGaps clears security_complete for each
// enrolled target the guardian's last pass (state) did not leave protected,
// and for each target whose recorded hook file is absent now (ownedFiles
// lists the files to look for). A signed-out account's target that waits for
// its next sign-in failed that pass without an error in the guardian status,
// so status and verify said the host was security-complete while its hook
// file was deleted (GAP-0146). Such a row and a missing file get a warning
// that names the account and the agent; any other failed row already fails
// the guardian status. A row of a removed account protects no one and is
// left to the enumerator, and a pending row was never enrolled.
func applyWindowsEnterpriseGuardianTargetGaps(
	result *enterprisestatus.Result,
	state enterpriseHookGuardianState,
	ownedFiles func(enterpriseHookReconcileRow) []string,
) {
	for _, row := range state.Results {
		if row.Pending {
			continue
		}
		connector := strings.TrimSpace(row.Connector)
		account := windowsEnterpriseGuardianRowAccount(row)
		if !row.OK {
			if enterpriseHookRemovedAccountRow(row) {
				continue
			}
			result.SecurityComplete = false
			if enterpriseHookAwaitingSignInError(row) {
				result.AddWarning(windowsEnterpriseGuardianRepairPendingCode, fmt.Sprintf(
					"the hook guardian's last pass could not verify %s for %s, and it repairs it only in that account's "+
						"own Windows session; that agent's hook calls may not be inspected until the account signs in "+
						"and the guardian repairs it", connector, account))
			}
			continue
		}
		if ownedFiles == nil {
			continue
		}
		var missing []string
		for _, path := range ownedFiles(row) {
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				missing = append(missing, path)
			}
		}
		if len(missing) == 0 {
			continue
		}
		result.SecurityComplete = false
		result.AddWarning(windowsEnterpriseGuardianRepairPendingCode, fmt.Sprintf(
			"%d DefenseClaw hook file(s) of %s for %s are missing since the hook guardian last verified them (%s); "+
				"that agent's hook calls may not be inspected until the guardian puts them back on its next pass",
			len(missing), account, connector, strings.Join(missing, ", ")))
	}
}

// windowsEnterpriseGuardianRowAccount names a guardian row's account: user,
// else profile folder, else SID.
func windowsEnterpriseGuardianRowAccount(row enterpriseHookReconcileRow) string {
	for _, value := range []string{row.User, row.UserHome, row.SID} {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return "an enrolled account"
}

// windowsEnterpriseGuardianRowHookFiles lists the hook config files the
// guardian recorded for a verified row, plus extra (files the guardian writes
// for the row beyond them), each once.
func windowsEnterpriseGuardianRowHookFiles(row enterpriseHookReconcileRow, extra []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	if row.Result != nil {
		for _, path := range row.Result.HookConfigPaths {
			add(path)
		}
	}
	for _, path := range extra {
		add(path)
	}
	sort.Strings(out)
	return out
}
