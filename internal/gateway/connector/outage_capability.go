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

// What a connector's DefenseClaw hook does with a call it cannot check
// because the gateway is not running, is still restarting or gives no answer
// in time (a gateway outage).
const (
	OutageBlocks = "blocks"
	OutageRuns   = "runs"
	// OutageFollowsGuardrailMode records different action and observe
	// outcomes for the selected per-user mode (Cursor).
	OutageFollowsGuardrailMode = "guardrail-mode"
)

// Whether a connector's hooks read DEFENSECLAW_STRICT_AVAILABILITY, which
// makes an outage block on a hook that would otherwise let the call run.
const (
	StrictAvailabilityRead          = "yes"
	StrictAvailabilityNotRead       = "no"
	StrictAvailabilityNotApplicable = "n/a"
)

// HookOutage is what a connector's hooks do during a gateway outage. The
// gateway outage table of the docs capability matrix
// (docs-site/data/capability-matrix.json, "outage") is a checked projection
// of it (enterprisepolicy TestDocsCapabilityMatrixOutageMatchesTheHooks),
// and every other docs page links to that table instead of restating it.
// The hook tests check each field against the rendered and running hooks.
type HookOutage struct {
	// PerUserClosed and PerUserOpen are the per-user hook installed with
	// fail mode closed or open.
	PerUserClosed string
	PerUserOpen   string
	// ManagedOpenUnixPerUserRoute is a managed standalone Linux or macOS hook
	// that the guardian writes for the user (a hook script or an in-agent
	// plugin on the hook socket) with the administrator's
	// hook_fail_mode: open. The machine-policy hook (defenseclaw-hook
	// --enterprise-managed) and every managed Windows hook follow the
	// administrator's mode, and closed (the default) blocks on every route.
	ManagedOpenUnixPerUserRoute string
	// SecureClientClosed is a Secure Client hook in fail mode closed.
	SecureClientClosed string
	StrictAvailability string
	// SecureClientEnvFailMode: under an authenticated Secure Client
	// deployment the hook still takes DEFENSECLAW_FAIL_MODE from the agent's
	// environment as a full override. No other hook reads it.
	SecureClientEnvFailMode bool
}

// managedUnixOutageClosed names the connectors whose per-user-route hooks a
// managed standalone Linux or macOS install (the hook socket) renders closed
// for an outage whatever hook_fail_mode says: the Copilot shell hook answers
// with Copilot's native deny (copilot_managed_failure), the Amp and OpenCode
// plugins with their native block. The render tests pin these exceptions.
var managedUnixOutageClosed = map[string]bool{"amp": true, "copilot": true, "opencode": true}

// strictAvailabilityExceptions are the hooks that do not read
// DEFENSECLAW_STRICT_AVAILABILITY; every other hook reads it.
var strictAvailabilityExceptions = map[string]string{"amp": StrictAvailabilityNotRead}

// secureClientEnvFailModeHooks are the shell hooks whose Secure Client
// delivery render (templateData.SecureClient) keeps the
// DEFENSECLAW_FAIL_MODE override (#1163).
var secureClientEnvFailModeHooks = map[string]bool{"antigravity": true, "devin": true, "hermes": true, "kiro": true}

// managedOutageProbeSocket marks a managed standalone Linux or macOS render
// (managedStandaloneRender) for ConnectorHookOutage; nothing is written.
const managedOutageProbeSocket = "/run/defenseclaw/hook.sock"

// ConnectorHookOutage returns conn's HookOutage. A proxy-backed connector
// has no hooks: while the gateway is down its requests are blocked whatever
// the fail mode.
func ConnectorHookOutage(conn Connector) HookOutage {
	name := normalizeConnectorName(conn.Name())
	if IsProxyConnector(name) {
		return HookOutage{
			PerUserClosed: OutageBlocks, PerUserOpen: OutageBlocks, ManagedOpenUnixPerUserRoute: OutageBlocks,
			SecureClientClosed: OutageBlocks, StrictAvailability: StrictAvailabilityNotApplicable,
		}
	}
	strict := StrictAvailabilityRead
	if exception, ok := strictAvailabilityExceptions[name]; ok {
		strict = exception
	}
	managedOpen := hookOutage(conn, SetupOpts{ManagedEnterprise: true, ManagedHookSocket: managedOutageProbeSocket, HookFailMode: "open"})
	if managedUnixOutageClosed[name] {
		managedOpen = OutageBlocks
	}
	return HookOutage{
		PerUserClosed:               perUserHookOutage(conn, "closed"),
		PerUserOpen:                 perUserHookOutage(conn, "open"),
		ManagedOpenUnixPerUserRoute: managedOpen,
		SecureClientClosed:          hookOutage(conn, SetupOpts{ManagedEnterprise: true, SecureClientHookDelivery: true, HookFailMode: "closed"}),
		StrictAvailability:          strict,
		SecureClientEnvFailMode:     secureClientEnvFailModeHooks[name],
	}
}

// perUserHookOutage is the outage outcome of conn's per-user hooks installed
// with mode, in observe and in action mode.
func perUserHookOutage(conn Connector, mode string) string {
	observe := hookOutage(conn, SetupOpts{HookFailMode: mode, ConfiguredHookFailMode: mode, GuardrailMode: "observe"})
	action := hookOutage(conn, SetupOpts{HookFailMode: mode, ConfiguredHookFailMode: mode, GuardrailMode: "action"})
	if observe != action {
		return OutageFollowsGuardrailMode
	}
	return observe
}

// hookOutage is the outage outcome of the fail mode conn's hooks are
// rendered with for opts (CapableHookFailMode).
func hookOutage(conn Connector, opts SetupOpts) string {
	if CapableHookFailMode(opts, conn, OutageHookFailMode(opts, conn)) == "closed" {
		return OutageBlocks
	}
	return OutageRuns
}
