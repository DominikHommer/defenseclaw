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
// That is the per-user Hermes hook on every OS. Hermes lets a call run when
// one of its hooks times out or cannot start, which is why
// SupportsFailClosed stays false, but it honours a block directive on the
// hook's stdout. The Linux and macOS hermes-hook.sh and the Windows native
// hook (hookexec) print one for every failure DefenseClaw itself sees when
// their fail mode is closed: the gateway is down or does not answer, its
// answer cannot be used, or the input is too large. Downgrading that render
// to "open" let a per-user Hermes tool call run during a gateway outage with
// a closed or unset hook_fail_mode (rel-1-0-3 GAP-0150 on Linux and macOS,
// GAP-0269 on Windows, where the downgraded value is the fail mode the
// native hook reads from .hookcfg), against the rule that hooks fail open
// only under Secure Client. An explicit "open" still renders open.
//
// Managed renders keep their own rules: a standalone render is closed for
// every connector (managedStandaloneRender), and Secure Client keeps Hermes
// open.
func hookBlocksItsOwnFailures(opts SetupOpts, conn Connector) bool {
	return conn != nil && conn.Name() == "hermes" && !opts.ManagedEnterprise
}
