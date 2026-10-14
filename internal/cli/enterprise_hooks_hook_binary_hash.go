// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/defenseclaw/defenseclaw/internal/gateway/connector"

// The guardian and each managed connector target use the same guarded digest
// memo. These functions are replaceable in guardian tests.
var (
	guardianTargetHookSHA256Hex = connector.ManagedEnterpriseHookBinarySHA256Hex
	guardianCopyHookSHA256Hex   = connector.ManagedProtectedHookCopySHA256Hex
)
