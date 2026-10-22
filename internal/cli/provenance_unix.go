//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

func provenanceManagedGatewayPID(ctx context.Context) (int, error) {
	env, err := enterpriseunix.NewEnv(runtime.GOOS, appVersion)
	if err != nil {
		return 0, err
	}
	for _, unit := range env.Services.Units() {
		if unit.Kind == "gateway" {
			status, err := env.Services.Status(ctx, unit)
			return status.PID, err
		}
	}
	return 0, fmt.Errorf("gateway service identity is unavailable")
}
