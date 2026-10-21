// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var connectorRefreshFailModesCmd = &cobra.Command{
	Use:   "refresh-fail-modes",
	Short: "Set the installed hooks' outage fail modes from the config (run by the installers)",
	Long: `Set the fail mode every installed per-user hook follows while the gateway
is down from config.yaml, without touching agent configuration or restarting
anything. hooks/.hookcfg and its flat records get the mode the config chooses,
and a connector hook script that bakes an open the config does not choose is
closed until the gateway renders it. The installers run it with the new
release's gateway before the running gateway stops and again once it is
stopped, so no hook follows an open an earlier release recorded for a mode
nobody set. An open the config sets stays open. A config this release cannot
load yet (a 0.8.x one before 'defenseclaw migrate') is read for its explicit
fail modes only. Managed installs are not changed.`,
	Hidden: true,
	// It runs beside the gateway it is about to replace: RunE loads the
	// config only (and still reads one it cannot load), never a second audit
	// store.
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
	Annotations:       map[string]string{auditOptionalAnnotation: "true"},
	RunE:              runConnectorRefreshFailModes,
}

func init() {
	connectorCmd.AddCommand(connectorRefreshFailModesCmd)
}

func runConnectorRefreshFailModes(cmd *cobra.Command, _ []string) error {
	mode, read, managedInstall := refreshFailModeResolver(cmd)
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		dataDir = config.DefaultDataPath()
	}
	var result connector.HookFailModeRefresh
	if !managedInstall {
		var err error
		result, err = connector.RefreshHookFailModes(filepath.Join(dataDir, "hooks"), mode)
		if err != nil {
			return fmt.Errorf("connector refresh-fail-modes: %w", err)
		}
	}
	if connectorFlagJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
			"action": "refresh-fail-modes", "ok": true, "config": read,
			"refreshed": nonNilStrings(result.Sidecar), "scripts": nonNilStrings(result.Scripts),
		})
	}
	if len(result.Sidecar) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Hook fail modes set from the config: %s\n", strings.Join(result.Sidecar, ", "))
	}
	if len(result.Scripts) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Hooks closed until the gateway starts: %s\n", strings.Join(result.Scripts, ", "))
	}
	return nil
}

// refreshFailModeResolver returns the outage fail mode the config chooses for
// each connector (connector.OutageHookFailMode: open only where the config
// sets it), how the config was read ("loaded" or "document"), and whether
// the install is managed, which is left alone.
func refreshFailModeResolver(cmd *cobra.Command) (func(string) string, string, bool) {
	if err := loadGatewayCommandConfigFor(cmd); err == nil && cfg != nil {
		if managed.IsManagedEnterprise(cfg.DeploymentMode) {
			return nil, "loaded", true
		}
		loaded := cfg
		reg := newConnectorRegistryWithPlugins()
		return func(name string) string {
			var conn connector.Connector
			if found, ok := reg.Get(name); ok && name != "" {
				conn = found
			}
			return connector.OutageHookFailMode(connector.SetupOpts{
				HookFailMode:             loaded.EffectiveHookFailModeForConnector(name),
				SecureClientHookDelivery: loaded.SecureClientIntegration(),
				GuardrailMode:            loaded.EffectiveGuardrailModeForConnector(name),
			}, conn)
		}, "loaded", false
	}
	// This release cannot load the config: a 0.8.x one before 'defenseclaw
	// migrate', which the installer's 'migrate --check' has just validated,
	// or none. Its explicit fail modes are the operator's (every migration
	// keeps them); everything else is closed, Cursor included.
	raw := readHookConfigDocument(config.ConfigPath())
	if config.ManagedEnterpriseDocument(raw) {
		return nil, "document", true
	}
	return func(name string) string {
		if config.ConfiguredHookFailModeInDocument(raw, name) == "open" {
			return "open"
		}
		return "closed"
	}, "document", false
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
