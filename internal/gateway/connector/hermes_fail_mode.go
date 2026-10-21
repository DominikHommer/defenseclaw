// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

// hookBlocksItsOwnFailures reports a connector whose rendered hook keeps the
// resolved "closed" fail mode although the agent itself has no fail-closed
// hook contract (HookCapability.SupportsFailClosed is false).
//
// That is the per-user Hermes, GitHub Copilot CLI and Antigravity hook on
// every OS. Each agent lets a call run when one of its hooks times out or
// cannot start, which is why SupportsFailClosed stays false, but each
// honours a denial on the hook's stdout: Hermes' block directive, Copilot's
// permissionDecision or behavior "deny", Antigravity's decision "deny". The
// Linux and macOS shell hooks and the Windows native hook (hookexec) print
// one for every failure DefenseClaw itself sees when their fail mode is
// closed: the gateway is down or does not answer, its answer cannot be used,
// or the input is too large. Lowering that render to "open" let a per-user
// tool call run during a gateway outage with a closed or unset
// hook_fail_mode (Hermes: rel-1-0-3 GAP-0150 on Linux and macOS, GAP-0269 on
// Windows, where the lowered value is the fail mode the native hook reads
// from .hookcfg; Copilot and Antigravity: r104 W3 G3-upg), against the rule
// that hooks fail open only under Secure Client. An explicit "open" still
// renders open.
//
// Managed renders keep their own rules: a standalone render is closed for
// every connector (managedStandaloneRender), and Secure Client keeps these
// connectors open.
func hookBlocksItsOwnFailures(opts SetupOpts, conn Connector) bool {
	if conn == nil || opts.ManagedEnterprise {
		return false
	}
	switch conn.Name() {
	case "hermes", "copilot", "antigravity":
		return true
	}
	return false
}
