//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

// provenanceManagedGateway is the gateway service of a standalone
// deployment and, under systemd socket activation, the service manager
// that holds the API socket with it.
func provenanceManagedGateway(ctx context.Context) (provenanceGateway, error) {
	env, err := enterpriseunix.NewEnv(runtime.GOOS, appVersion)
	if err != nil {
		return provenanceGateway{}, err
	}
	pid, manager, err := env.GatewayAPIListener(ctx)
	return provenanceGateway{PID: pid, SocketManagerPID: manager}, err
}

// provenanceCommittedConfig reads the root-only copy of the config the
// standalone lifecycle last applied. A seam for tests.
var provenanceCommittedConfig = func() ([]byte, error) {
	env, err := enterpriseunix.NewEnv(runtime.GOOS, appVersion)
	if err != nil {
		return nil, err
	}
	return env.ReadCommittedConfig()
}
