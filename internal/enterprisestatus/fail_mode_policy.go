// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import "github.com/defenseclaw/defenseclaw/internal/config"

// CodeFailOpenIgnored: a hook_fail_mode or ACP fail_mode of open that a
// managed deployment outside Secure Client ignores, because its hooks always
// fail closed (config.ManagedFailOpenWarnings).
const CodeFailOpenIgnored = "fail_open_ignored"

// AddFailModePolicyWarnings adds, never as an error, each fail-open setting
// cfg's managed deployment ignores, so ensure, status and verify say why the
// hooks report closed although the config says open. On a standalone
// deployment it also lists the resolved hook fail mode of each of
// connectors (the connectors the deployment protects) in HookFailModes, so
// an administrator can read what every connector's hooks do on an outage.
// The Linux, macOS and Windows lifecycles share it.
func (r *Result) AddFailModePolicyWarnings(cfg *config.Config, connectors []string) {
	if r == nil || cfg == nil {
		return
	}
	for _, warning := range cfg.ManagedFailOpenWarnings() {
		r.AddWarning(CodeFailOpenIgnored, warning)
	}
	if !cfg.StandaloneEnterprise() || len(connectors) == 0 {
		return
	}
	r.HookFailModes = make(map[string]string, len(connectors))
	for _, name := range connectors {
		r.HookFailModes[name] = cfg.EffectiveHookFailModeForConnector(name)
	}
}
