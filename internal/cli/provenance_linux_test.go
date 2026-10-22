// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
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
	stubProvenanceSeams(t)
	// The gateway's environment has no token: it authenticates with the
	// inline one. Who holds the listener and each connection is real.
	provenanceGatewayEnvironment = func(int, string) ([]string, error) { return nil, nil }
	gatewayPortHolders = daemon.FindPortHolders
	cfg = provenanceTestConfigAt(host, portNumber)
	cmd, out, _ := provenanceTestCommand()
	requests := func() int {
		entries, _ := filepath.Glob(filepath.Join(dir, "request-*"))
		return len(entries)
	}
	provenanceGatewayIdentity = func(context.Context, []net.IP, int) (provenanceGateway, error) {
		return provenanceGateway{PID: child.Process.Pid}, nil
	}
	if err := runProvenanceShow(cmd, nil); err == nil || out.Len() != 0 || requests() != 0 {
		t.Fatalf("a socket held by an unknown second process: output=%q error=%v requests=%d", out, err, requests())
	}
	provenanceGatewayIdentity = func(context.Context, []net.IP, int) (provenanceGateway, error) {
		return provenanceGateway{PID: child.Process.Pid, SocketManagerPID: os.Getpid()}, nil
	}
	if err := runProvenanceShow(cmd, nil); err != nil || out.String() == "" || requests() != 1 {
		t.Fatalf("socket-activated gateway: output=%q error=%v requests=%d", out, err, requests())
	}
	if !strings.Contains(out.String(), "generation: 12\n") {
		t.Fatalf("output = %q, want generation 12", out)
	}
}

// The binding finding: a PID record of this home names whatever process it
// was written for. Here it is the strongest kind (this home's data
// directory, the process's executable and kernel start identity) and names
// another program of this account, which the kernel shows holding the API
// listener. Before, provenance sent that program the gateway token. Now the
// program is not this DefenseClaw binary, so the gateway is not verified
// and nothing is sent.
func TestProvenanceShowSendsNoTokenToAProcessAPIDRecordNames(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	gateway := newProvenanceTestGateway()
	server := httptest.NewServer(gateway)
	defer server.Close()
	stubProvenanceSeams(t)
	cfg = provenanceTestConfig(t, server)
	other := otherProvenanceProgram(t)
	pid := other.Process.Pid
	executable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		t.Fatal(err)
	}
	tail := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+2:]))
	record, err := json.Marshal(map[string]any{"pid": pid, "executable": executable, "data_dir": home,
		"start_identity": tail[19], "start_time": time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, daemon.PIDFileName), record, 0o600); err != nil {
		t.Fatal(err)
	}
	if !daemon.New(home).HasManagedProcessIdentity(pid) {
		t.Fatal("precondition: this home's current PID record must prove the process it names")
	}
	gatewayPortHolders = func(string, int) ([]daemon.PortHolder, error) {
		return []daemon.PortHolder{{PID: pid, UID: os.Getuid()}}, nil
	}
	cmd, out, _ := provenanceTestCommand()
	err = runProvenanceShow(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "gateway not verified") || out.Len() != 0 {
		t.Fatalf("output=%q error=%v", out, err)
	}
	if gateway.requests.Load() != 0 || gateway.credentialed.Load() != 0 {
		t.Fatalf("sent %d requests, %d with the gateway credential, to the process a PID record names",
			gateway.requests.Load(), gateway.credentialed.Load())
	}
}
