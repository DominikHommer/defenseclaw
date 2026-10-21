//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/managed"

// standaloneHookSessionDir is the protected session record folder of the
// Windows standalone layout, from the protected ProgramData registration.
func standaloneHookSessionDir() (string, error) {
	layout, err := managed.StandaloneWindowsLayout()
	return layout.HookSessionDir, err
}
