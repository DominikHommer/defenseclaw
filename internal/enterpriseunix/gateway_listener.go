// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"slices"
	"strings"
)

// systemdManagerPID is the PID of the systemd system manager.
const systemdManagerPID = 1

// GatewayAPIListener names the processes that may hold the gateway's API
// listening socket: the running gateway service (gatewayPID) and, under
// systemd socket activation, the service manager (socketManagerPID, else
// 0). On Linux defenseclaw-gateway-api.socket owns the loopback listener
// and passes it to defenseclaw-gateway.service, so PID 1 holds the same
// socket as the gateway. The service manager counts only while that socket
// unit is active, listens on the deployment's API address, accepts no
// connections itself (Accept=no) and triggers the gateway service. launchd
// passes no socket: the gateway binds its own.
func (e *Env) GatewayAPIListener(ctx context.Context) (gatewayPID, socketManagerPID int, err error) {
	e.fillDefaults()
	var gateway *Unit
	for _, unit := range e.Services.Units() {
		if unit.Kind == "gateway" {
			gateway = &unit
			break
		}
	}
	if gateway == nil {
		return 0, 0, errors.New("gateway service identity is unavailable")
	}
	status, err := e.Services.Status(ctx, *gateway)
	if err != nil {
		return 0, 0, err
	}
	if status.PID <= 0 {
		return 0, 0, errors.New("the gateway service is not running")
	}
	systemd, ok := e.Services.(*systemdManager)
	if !ok {
		return status.PID, 0, nil
	}
	socket := systemd.properties(ctx, unitAPISocket, "ActiveState", "Accept", "Triggers", "Listen")
	listen, _, _ := strings.Cut(socket["Listen"], " (")
	if socket["ActiveState"] != "active" || socket["Accept"] != "no" ||
		!slices.Contains(strings.Fields(socket["Triggers"]), gateway.Name) ||
		strings.TrimSpace(listen) != e.Layout.APIAddr {
		return status.PID, 0, nil
	}
	return status.PID, systemdManagerPID, nil
}
