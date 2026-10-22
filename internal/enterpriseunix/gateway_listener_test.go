// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"strings"
	"testing"
)

// PID 1 may hold the gateway API socket only as the systemd socket unit
// that listens on the deployment's API address and hands it to the gateway
// service; any other socket unit state leaves the gateway as the only
// holder a reader may trust.
func TestGatewayAPIListenerTrustsSystemdOnlyForTheActivatingSocket(t *testing.T) {
	const gatewayShow = "systemctl show defenseclaw-gateway.service -p ActiveState -p SubState -p UnitFileState -p MainPID -p NRestarts"
	const socketShow = "systemctl show defenseclaw-gateway-api.socket -p ActiveState -p Accept -p Triggers -p Listen"
	activated := "ActiveState=active\nAccept=no\nTriggers=defenseclaw-gateway.service\nListen=127.0.0.1:18970 (Stream)\n"
	for _, tc := range []struct {
		name, gateway, socket string
		gatewayPID, manager   int
		err                   bool
	}{
		{"socket activated", "ActiveState=active\nSubState=running\nMainPID=4242\n", activated, 4242, 1, false},
		{"socket stopped", "ActiveState=active\nMainPID=4242\n", strings.Replace(activated, "=active", "=inactive", 1), 4242, 0, false},
		{"accepting socket", "ActiveState=active\nMainPID=4242\n", strings.Replace(activated, "Accept=no", "Accept=yes", 1), 4242, 0, false},
		{"another service", "ActiveState=active\nMainPID=4242\n", strings.Replace(activated, "defenseclaw-gateway.service", "other.service", 1), 4242, 0, false},
		{"another address", "ActiveState=active\nMainPID=4242\n", strings.Replace(activated, "127.0.0.1:18970", "0.0.0.0:18970", 1), 4242, 0, false},
		{"no socket unit", "ActiveState=active\nMainPID=4242\n", "", 4242, 0, false},
		{"gateway stopped", "ActiveState=inactive\nMainPID=0\n", activated, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{replies: map[string]fakeReply{
				gatewayShow: {result: CommandResult{Stdout: []byte(tc.gateway)}},
				socketShow:  {result: CommandResult{Stdout: []byte(tc.socket)}},
			}}
			env := &Env{GOOS: "linux", Runner: runner}
			env.Layout.APIAddr = "127.0.0.1:18970"
			env.Services = &systemdManager{env: env}
			pid, manager, err := env.GatewayAPIListener(context.Background())
			if (err != nil) != tc.err || pid != tc.gatewayPID || manager != tc.manager {
				t.Fatalf("GatewayAPIListener = %d, %d, %v; want %d, %d (error %v)", pid, manager, err, tc.gatewayPID, tc.manager, tc.err)
			}
		})
	}
}
