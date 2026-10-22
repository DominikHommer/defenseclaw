// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// The real socket-activation topology: one process (systemd's role) owns
// the listening socket and passes it to the gateway process, which serves
// on it, so both hold the one socket. provenance show reads the gateway
// when the passing process is the gateway's socket manager, and sends
// nothing when it is not.
func TestProvenanceShowUnderSocketActivation(t *testing.T) {
	const childDir = "DC_TEST_PROVENANCE_ACTIVATED_GATEWAY"
	if dir := os.Getenv(childDir); dir != "" {
		listener, err := net.FileListener(os.NewFile(3, "api"))
		if err != nil {
			t.Fatal(err)
		}
		gateway := newProvenanceTestGateway()
		gateway.live.Generation = 12
		served := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = os.WriteFile(filepath.Join(dir, "request-"+strconv.FormatInt(time.Now().UnixNano(), 10)), nil, 0o600)
			gateway.ServeHTTP(w, r)
		})
		if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = http.Serve(listener, served)
		t.Fatal("the gateway stopped serving")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	passed, err := listener.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(binary, "-test.run=^TestProvenanceShowUnderSocketActivation$")
	child.Env = append(os.Environ(), childDir+"="+dir)
	child.ExtraFiles = []*os.File{passed}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	_ = passed.Close() // This process keeps only the listener it never accepts on.
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the activated gateway did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	portNumber, _ := strconv.Atoi(port)
	holders, err := daemon.FindPortHolders(host, portNumber)
	pids := make([]int, 0, len(holders))
	for _, holder := range holders {
		pids = append(pids, holder.PID)
	}
	if err != nil || len(pids) != 2 || !slices.Contains(pids, os.Getpid()) || !slices.Contains(pids, child.Process.Pid) {
		t.Fatalf("holders of the passed socket = %v, %v; want this process and the gateway", pids, err)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	previous, oldIdentity, oldHolders := cfg, provenanceGatewayIdentity, gatewayPortHolders
	t.Cleanup(func() { cfg, provenanceGatewayIdentity, gatewayPortHolders = previous, oldIdentity, oldHolders })
	gatewayPortHolders = daemon.FindPortHolders
	cfg = provenanceTestConfigAt(host, portNumber)
	cmd, out, _ := provenanceTestCommand()
	requests := func() int {
		entries, _ := filepath.Glob(filepath.Join(dir, "request-*"))
		return len(entries)
	}
	provenanceGatewayIdentity = func(context.Context) (provenanceGateway, error) {
		return provenanceGateway{PID: child.Process.Pid}, nil
	}
	if err := runProvenanceShow(cmd, nil); err == nil || out.Len() != 0 || requests() != 0 {
		t.Fatalf("a socket held by an unknown second process: output=%q error=%v requests=%d", out, err, requests())
	}
	provenanceGatewayIdentity = func(context.Context) (provenanceGateway, error) {
		return provenanceGateway{PID: child.Process.Pid, SocketManagerPID: os.Getpid()}, nil
	}
	if err := runProvenanceShow(cmd, nil); err != nil || out.String() == "" || requests() != 1 {
		t.Fatalf("socket-activated gateway: output=%q error=%v requests=%d", out, err, requests())
	}
	if !strings.Contains(out.String(), "generation: 12\n") {
		t.Fatalf("output = %q, want generation 12", out)
	}
}
