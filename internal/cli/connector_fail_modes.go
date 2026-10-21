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

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var connectorRefreshFailModesCmd = &cobra.Command{
	Use:   "refresh-fail-modes",
	Short: "Rewrite the hooks' fail modes from the config (run by the installers)",
	Long: `Rewrite the fail mode of every connector in hooks/.hookcfg with the mode
this release renders from config.yaml, without touching agent configuration
or restarting anything. The installers run it with the new release's gateway
before the running gateway stops and the new hook goes in, so no hook follows
an open an earlier release recorded for a mode nobody set. An open the config
sets stays open. Managed installs are not changed.`,
	Hidden: true,
	// It runs beside the gateway it is about to replace: load the config
	// only, never a second audit store.
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		return loadGatewayCommandConfigFor(cmd)
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
	Annotations:       map[string]string{auditOptionalAnnotation: "true"},
	RunE:              runConnectorRefreshFailModes,
}

func init() {
	connectorCmd.AddCommand(connectorRefreshFailModesCmd)
}

func runConnectorRefreshFailModes(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		return fmt.Errorf("connector refresh-fail-modes: no data directory configured (set --data-dir)")
	}
	var refreshed []string
	if cfg != nil && !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		reg := newConnectorRegistryWithPlugins()
		var err error
		refreshed, err = connector.RefreshHookFailModes(filepath.Join(dataDir, "hooks"), func(name string) string {
			conn, ok := reg.Get(name)
			if !ok {
				return ""
			}
			return connector.RenderedHookFailMode(connector.SetupOpts{
				HookFailMode:             cfg.EffectiveHookFailModeForConnector(name),
				SecureClientHookDelivery: cfg.SecureClientIntegration(),
				GuardrailMode:            cfg.EffectiveGuardrailModeForConnector(name),
			}, conn)
		})
		if err != nil {
			return fmt.Errorf("connector refresh-fail-modes: %w", err)
		}
	}
	if connectorFlagJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
			"action": "refresh-fail-modes", "ok": true, "refreshed": nonNilStrings(refreshed),
		})
	}
	if len(refreshed) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Hook fail modes rendered from the config: %s\n", strings.Join(refreshed, ", "))
	}
	return nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
