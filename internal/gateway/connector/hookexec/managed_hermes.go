// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"strings"
)

// managedHermesBlocks reports a Hermes pre_tool_call of a managed hook
// outside Secure Client. Hermes has no fail-closed hook contract of its own
// (failOpenOnly: a timeout, a spawn error or an empty answer lets the call
// run), but it blocks a tool call whose hook prints its block directive. A
// managed deployment outside Secure Client fails closed (owner rule
// 2026-10-14), so there the native hook prints that directive whenever it
// cannot get a verdict, as the Linux and macOS shell hook does
// (rel-1-0-2 GAP-0423). Per-user and Secure Client hooks, and every other
// Hermes event, keep the neutral result.
func managedHermesBlocks(opts Options, sp spec) bool {
	return sp.connector == "hermes" && managedNativeDecision(opts) &&
		strings.EqualFold(strings.TrimSpace(opts.Event), "pre_tool_call")
}

// managedHermesFailClosed blocks a managed Hermes tool call DefenseClaw
// could not check (managedHermesBlocks) with Hermes' native block directive
// and the plain text of managedStandaloneFailClosedText for layer, so Hermes
// says why: for example that the DefenseClaw gateway service is not
// running. handled is false for every other invocation.
func managedHermesFailClosed(opts Options, sp spec, layer, reason string) (int, bool) {
	if !managedHermesBlocks(opts, sp) {
		return 0, false
	}
	text := managedStandaloneFailClosedText(opts.Event, layer, reason)
	switch reason {
	case managedSIDUnregisteredReason, managedEnrollmentPendingReason:
		text = "DefenseClaw blocked this tool call: " + unenrolledAccountExplanation + "."
	case managedUIDUnregisteredReason:
		text = "DefenseClaw blocked this tool call: " + unixUnenrolledAccountExplanation + "."
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: blocking managed %s (fail mode closed): %s\n", sp.subject, reason)
	fmt.Fprintln(opts.Stdout, `{"action":"block","message":`+mustJSONString(text)+`}`)
	return 0, true
}

// failOpenOnlyCloses reports whether a connector without a fail-closed hook
// contract (failOpenOnly) still blocks this failed invocation: a managed
// Copilot tool call or permission request (managedCopilotFailClosed) or a
// managed Hermes tool call (managedHermesBlocks). The hook-failure log
// records that outcome, not the configured fail mode, so a call that ran
// fail-open is reported as one (rel-1-0-2 GAP-0446).
func failOpenOnlyCloses(opts Options, sp spec) bool {
	switch sp.connector {
	case "copilot":
		if !opts.ManagedEnterprise {
			return false
		}
		if sp.dialect == copilotVSCodeLocalSurface {
			return copilotVSCodeLocalOutput(opts.Event, "block", failedClosed) != ""
		}
		return opts.Event == "preToolUse" || opts.Event == "permissionRequest"
	case "hermes":
		return managedHermesBlocks(opts, sp)
	}
	return false
}

// loggedFailMode is the fail mode a hook-failure line records: the outcome
// for a failOpenOnly connector (failOpenOnlyCloses), the given one otherwise.
func loggedFailMode(opts Options, sp spec, failMode string) string {
	if !sp.failOpenOnly {
		return failMode
	}
	if failOpenOnlyCloses(opts, sp) {
		return "closed"
	}
	return "open"
}
