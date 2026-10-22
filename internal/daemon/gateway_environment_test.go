// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || windows

package daemon

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"
)

const gatewayEnvironmentHelperEnv = "DEFENSECLAW_TEST_GATEWAY_ENVIRONMENT_HELPER"

func TestGatewayEnvironmentHelperProcess(*testing.T) {
	if os.Getenv(gatewayEnvironmentHelperEnv) != "1" {
		return
	}
	time.Sleep(time.Minute)
	os.Exit(0)
}

// GatewayEnvironment is the environment of the process proven with that
// start identity, and of no other.
func TestGatewayEnvironmentIsTheProvenProcesssEnvironment(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestGatewayEnvironmentHelperProcess$")
	cmd.Env = append(os.Environ(), gatewayEnvironmentHelperEnv+"=1", "DEFENSECLAW_GATEWAY_TOKEN=token of the gateway")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	pid := cmd.Process.Pid
	var identity string
	for deadline := time.Now().Add(10 * time.Second); identity == ""; time.Sleep(10 * time.Millisecond) {
		identity, _ = processStartIdentity(pid)
		if time.Now().After(deadline) {
			t.Fatal("the helper's start identity is unreadable")
		}
	}
	var environment []string
	var err error
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		environment, err = GatewayEnvironment(pid, identity)
		if err == nil && slices.Contains(environment, "DEFENSECLAW_GATEWAY_TOKEN=token of the gateway") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("environment of the proven process = %d entries, %v", len(environment), err)
		}
	}
	for _, tc := range []struct {
		pid      int
		identity string
	}{{pid, identity + "0"}, {pid, ""}, {0, identity}} {
		if _, err := GatewayEnvironment(tc.pid, tc.identity); !errors.Is(err, ErrGatewayNotVerified) {
			t.Fatalf("GatewayEnvironment(%d, %q) = %v; want not verified", tc.pid, tc.identity, err)
		}
	}
}
