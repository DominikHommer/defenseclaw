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
// hooks report closed although the config says open. The resolved fail mode
// of each connector is the status v2 connectors block's
// effective_hook_fail_mode (enterprisehooks.ManagedHookFailMode). The Linux,
// macOS and Windows lifecycles share it.
func (r *Result) AddFailModePolicyWarnings(cfg *config.Config) {
	if r == nil || cfg == nil {
		return
	}
	for _, warning := range cfg.ManagedFailOpenWarnings() {
		r.AddWarning(CodeFailOpenIgnored, warning)
	}
}
