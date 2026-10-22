//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package processutil

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const darwinTreeHelper = "DC_PROCESSUTIL_DARWIN_TREE_HELPER"

func TestDarwinTreeGatewayExitHelper(t *testing.T) {
	pidFile := os.Getenv(darwinTreeHelper)
	if pidFile == "" {
		t.Skip("helper for TestDarwinTreeDiesWithGateway")
	}
	go func() {
		_ = RunTree(exec.Command("/bin/sh", "-c", `sleep 60 & echo $! > "$1"; wait`, "sh", pidFile))
	}()
	if _, err := waitDarwinChildPID(pidFile); err != nil {
		os.Exit(2)
	}
	os.Exit(3)
}

func waitDarwinChildPID(path string) (int, error) {
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err == nil && pid > 1 {
			return pid, nil
		}
	}
	return 0, errors.New("scanner helper did not publish its PID")
}

func darwinChildGone(pid int) bool {
	err := syscall.Kill(pid, 0)
	return errors.Is(err, syscall.ESRCH)
}

func requireDarwinChildGone(t *testing.T, pid int) {
	t.Helper()
	t.Cleanup(func() {
		if !darwinChildGone(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if darwinChildGone(pid) {
			return
		}
	}
	t.Fatalf("scanner helper %d outlived its process tree", pid)
}

func TestDarwinTreeDiesWithGateway(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "scanner.pid")
	gateway := exec.Command(os.Args[0], "-test.run=^TestDarwinTreeGatewayExitHelper$", "-test.count=1")
	gateway.Env = append(os.Environ(), darwinTreeHelper+"="+pidFile)
	err := gateway.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("gateway helper = %v, want exit 3 after scanner starts", err)
	}
	pid, err := waitDarwinChildPID(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	requireDarwinChildGone(t, pid)
}

func TestDarwinTreeCancellationEndsDescendants(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "scanner.pid")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cmd := CommandContext(ctx, "/bin/sh", "-c", `sleep 60 & echo $! > "$1"; wait`, "sh", pidFile)
	finished := make(chan error, 1)
	go func() { finished <- RunTree(cmd) }()
	pid, err := waitDarwinChildPID(pidFile)
	if err != nil {
		cancel()
		<-finished
		t.Fatal(err)
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("RunTree did not finish after cancellation")
	}
	requireDarwinChildGone(t, pid)
}

const darwinLeaderExited = "DC_PROCESSUTIL_DARWIN_LEADER_EXITED"

// TestDarwinTreeLeaderExitedHelper is the gateway of
// TestDarwinTreeGatewayDiesAfterTheScannerExits: its scanner starts a helper
// and exits; the gateway then stops before its own cleanup and waits to be
// killed.
func TestDarwinTreeLeaderExitedHelper(t *testing.T) {
	dir := os.Getenv(darwinLeaderExited)
	if dir == "" {
		t.Skip("gateway of TestDarwinTreeGatewayDiesAfterTheScannerExits")
	}
	afterDarwinLeaderExit = func() {
		_ = os.WriteFile(filepath.Join(dir, "exited"), nil, 0o600)
		time.Sleep(time.Minute)
	}
	_ = RunTree(exec.Command("/bin/sh", "-c", `sleep 60 & echo $! > "$1.tmp" && mv "$1.tmp" "$1"; exit 0`,
		"sh", filepath.Join(dir, "helper.pid")))
}

// The gateway dies after the scanner leader exited and before its cleanup
// killed the group: the watchdog, a member of that group, still ends what
// the scanner left behind (W4b2 scanner, loop round 1).
func TestDarwinTreeGatewayDiesAfterTheScannerExits(t *testing.T) {
	if os.Getenv(darwinLeaderExited) != "" {
		t.Skip("running as the gateway")
	}
	dir := t.TempDir()
	gateway := exec.Command(os.Args[0], "-test.run=^TestDarwinTreeLeaderExitedHelper$", "-test.count=1")
	gateway.Env = append(os.Environ(), darwinLeaderExited+"="+dir)
	if err := gateway.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Process.Kill(); _ = gateway.Wait() })
	pid, err := waitDarwinChildPID(filepath.Join(dir, "helper.pid"))
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(filepath.Join(dir, "exited")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("the gateway never saw its scanner exit")
		}
	}
	if darwinChildGone(pid) {
		t.Fatalf("helper %d ended before the gateway died; the test proves nothing", pid)
	}
	if err := gateway.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = gateway.Wait()
	requireDarwinChildGone(t, pid)
}
