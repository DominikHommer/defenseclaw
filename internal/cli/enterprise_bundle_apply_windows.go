// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// runEnterpriseBundleApply: Windows applies bundles through Setup
// (/ensure BUNDLE=), which a later stack item wires; this build refuses
// before anything changes.
func runEnterpriseBundleApply(cmd *cobra.Command, opts *bundleApplyOptions) error {
	if bundleSecureClient() {
		return bundleApplyRefused(cmd, opts.json, secureClientBundleRefusal())
	}
	return bundleApplyRefused(cmd, opts.json, &enterprisebundle.Error{Code: enterprisebundle.CodeNotManaged,
		Detail: "bundle apply is not available on Windows in this build"})
}
