// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

var nativeSandboxProfileLoad = loadNativeSandboxHookProfile

// A native session uses the existing hook argv/event forms. Only its trusted
// fixed Linux runtime directory selects the transport; no new command argument
// or inherited environment chooses a socket, token, receipt or policy.
func nativeSandboxHookOptions(connector, event string) (hookexec.Options, bool) {
	profile, present, err := nativeSandboxProfileLoad()
	if !present {
		return hookexec.Options{}, false
	}
	if err != nil || profile == nil || profile.Connector != connector {
		profile = &hookexec.NativeSandboxProfile{} // stays native and refuses
	}
	return hookexec.Options{
		Connector: connector, Event: event, NativeSandbox: profile,
		HookContractID: profile.HookContract, HookSurface: profile.HookSurface,
		FailMode: "closed", StrictAvailability: true,
		Home: hookexec.NativeSandboxHookDirectory, HookDir: hookexec.NativeSandboxHookDirectory,
		// Tracing is untrusted metadata, format-checked by the existing sender.
		// It never selects native transport, identity or policy.
		TraceParent: hookFirstNonEmpty(envvars.Getenv("DEFENSECLAW_TRACEPARENT"), os.Getenv("TRACEPARENT"), os.Getenv("OTEL_TRACEPARENT")),
		TraceState:  hookFirstNonEmpty(envvars.Getenv("DEFENSECLAW_TRACESTATE"), os.Getenv("TRACESTATE"), os.Getenv("OTEL_TRACESTATE")),
	}, true
}
