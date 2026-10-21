// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ManagedEnterpriseDocument reports a config.yaml document whose
// deployment_mode is managed_enterprise, without loading the config.
func ManagedEnterpriseDocument(data []byte) bool {
	var doc struct {
		DeploymentMode string `yaml:"deployment_mode"`
	}
	return yaml.Unmarshal(data, &doc) == nil && managed.IsManagedEnterprise(doc.DeploymentMode)
}

// ConfiguredHookFailModeInDocument is the hook fail mode a config.yaml
// document sets explicitly for a per-user connector, canonicalized as the
// config resolver does (configuredHookFailModeForConnector): the connector's
// guardrail.connectors entry, then guardrail.hook_fail_mode. It reads only
// those keys, so a native hook can check its sidecar against the config
// without loading it. It is "" when the document sets neither, does not
// parse, turns automatic protection on (its overlay decides then), or names
// Cursor, whose per-user mode follows its guardrail mode: callers treat ""
// as closed.
func ConfiguredHookFailModeInDocument(data []byte, connector string) string {
	if normalizeConnectorKey(connector) == "cursor" {
		return ""
	}
	var doc struct {
		Guardrail struct {
			HookFailMode string `yaml:"hook_fail_mode"`
			Connectors   map[string]struct {
				HookFailMode string `yaml:"hook_fail_mode"`
			} `yaml:"connectors"`
		} `yaml:"guardrail"`
		ApplicationProtection struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"application_protection"`
	}
	if yaml.Unmarshal(data, &doc) != nil || doc.ApplicationProtection.Enabled {
		return ""
	}
	c := &Config{Guardrail: GuardrailConfig{HookFailMode: strings.TrimSpace(doc.Guardrail.HookFailMode)}}
	if len(doc.Guardrail.Connectors) > 0 {
		c.Guardrail.Connectors = make(map[string]PerConnectorGuardrailConfig, len(doc.Guardrail.Connectors))
		for name, entry := range doc.Guardrail.Connectors {
			c.Guardrail.Connectors[name] = PerConnectorGuardrailConfig{HookFailMode: entry.HookFailMode}
		}
	}
	return c.configuredHookFailModeForConnector(connector)
}
