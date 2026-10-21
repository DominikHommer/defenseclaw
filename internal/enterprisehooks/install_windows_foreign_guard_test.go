// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// windowsGuardCaptureConnector stands in for the Amp and OpenCode plugin
// connectors and records the foreign-hook guard binary the generic Windows
// lifecycle hands them when it renders the plugin (Setup) and whenever it
// lays out or verifies the footprint (AgentPaths).
type windowsGuardCaptureConnector struct {
	windowsGenericPluginTokenTestConnector
	rendered *[]string
	seen     *[]string
}

func (c *windowsGuardCaptureConnector) Setup(ctx context.Context, opts connector.SetupOpts) error {
	*c.rendered = append(*c.rendered, opts.ForeignHookGuardBinary)
	return c.windowsGenericPluginTokenTestConnector.Setup(ctx, opts)
}

func (c *windowsGuardCaptureConnector) AgentPaths(opts connector.SetupOpts) connector.AgentPaths {
	*c.seen = append(*c.seen, opts.ForeignHookGuardBinary)
	return c.windowsGenericPluginTokenTestConnector.AgentPaths(opts)
}

var errTestUntrustedGuard = errors.New("test: untrusted guard binary")
