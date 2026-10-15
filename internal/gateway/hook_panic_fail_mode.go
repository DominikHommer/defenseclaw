// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// explicitHookFailOpen reports an operator-selected open setting. The
// effective accessor can also return open for an observe-only connector,
// while a request profile or legacy hook setting may select action mode.
func explicitHookFailOpen(cfg *config.Config, connectorName string) bool {
	if cfg == nil {
		return false
	}
	if cfg.ApplicationProtection.Enabled && !cfg.ManualConnectorConfigured(connectorName) {
		overlay := cfg.ApplicationProtection.Guardrail
		for name, entry := range cfg.ApplicationProtection.Connectors {
			if config.NormalizeConnectorName(name) == config.NormalizeConnectorName(connectorName) {
				overlay = entry.Guardrail
				break
			}
		}
		if mode := strings.TrimSpace(overlay.HookFailMode); mode != "" {
			return strings.EqualFold(mode, "open")
		}
	}
	for name, entry := range cfg.Guardrail.Connectors {
		if config.NormalizeConnectorName(name) == config.NormalizeConnectorName(connectorName) {
			if mode := strings.TrimSpace(entry.HookFailMode); mode != "" {
				return strings.EqualFold(mode, "open")
			}
			break
		}
	}
	return strings.EqualFold(strings.TrimSpace(cfg.Guardrail.HookFailMode), "open")
}
