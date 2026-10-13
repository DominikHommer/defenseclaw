// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/enterprisehooks"

// Only the standalone Windows guardian records the targets it put back
// (GAP-0440); Secure Client is unchanged.
func init() {
	enterpriseHookGuardianRestoresEnabled = enterprisehooks.WindowsStandaloneProcess
}
