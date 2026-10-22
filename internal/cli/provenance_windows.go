// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io/fs"
)

// provenanceManagedGateway is the gateway service of a standalone
// deployment; it binds its API socket itself.
func provenanceManagedGateway(context.Context) (provenanceGateway, error) {
	return provenanceGateway{PID: int(windowsStandaloneGatewayPID())}, nil
}

// provenanceCommittedConfig: the Windows deployment keeps no copy of the
// last applied config. A seam for tests.
var provenanceCommittedConfig = func() ([]byte, error) { return nil, fs.ErrNotExist }
