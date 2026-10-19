// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package cli

import "github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"

// Windows process containers need their own trusted DOS descriptor and pipe
// transport. The Linux mount path is never selected on another platform.
func loadNativeSandboxHookProfile() (*hookexec.NativeSandboxProfile, bool, error) {
	return nil, false, nil
}
