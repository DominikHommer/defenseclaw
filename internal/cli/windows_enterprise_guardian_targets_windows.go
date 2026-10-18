//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsEnterpriseGuardianStateForStatus reads the standalone guardian's
// last pass; tests replace it.
var windowsEnterpriseGuardianStateForStatus = func() (enterpriseHookGuardianState, bool, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return enterpriseHookGuardianState{}, false, err
	}
	return loadEnterpriseHookGuardianState(layout.DataDir)
}

// windowsEnterpriseCopilotVSCodeHookFileWanted reports whether the guardian
// writes the VS Code Local hook file for Copilot targets under the loaded
// config; false when that cannot be told. Tests replace it.
var windowsEnterpriseCopilotVSCodeHookFileWanted = func() bool {
	opts, ok, err := windowsCopilotVSCodeUserOptions(false)
	if err != nil || !ok {
		return false
	}
	hookFile, _ := enterprisepolicy.CopilotVSCodeUserWant(opts)
	return hookFile
}

// applyWindowsEnterpriseGuardianTargets applies the guardian's last pass and
// the targets' hook files to status and verify (GAP-0146). An unreadable or
// missing guardian state is left to the guardian status, which fails on it.
func applyWindowsEnterpriseGuardianTargets(result *enterprisestatus.Result) {
	state, exists, err := windowsEnterpriseGuardianStateForStatus()
	if err != nil || !exists {
		return
	}
	copilotHookFile := windowsEnterpriseCopilotVSCodeHookFileWanted()
	applyWindowsEnterpriseGuardianTargetGaps(result, state, func(row enterpriseHookReconcileRow) []string {
		var extra []string
		if copilotHookFile {
			_, extra = enterpriseHookPlatformWatchFiles(row.Connector, row.UserHome)
		}
		return windowsEnterpriseGuardianRowHookFiles(row, extra)
	})
}
