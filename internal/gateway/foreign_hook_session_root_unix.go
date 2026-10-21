//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// standaloneHookSessionDir is the protected session record folder of the
// Linux or macOS standalone layout.
func standaloneHookSessionDir() (string, error) {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	return layout.HookSessionDir, err
}
