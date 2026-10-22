// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// startCopiedSleep copies sleep to dir/name and runs it, so the test can
// replace or move the file while it runs.
func startCopiedSleep(t *testing.T, dir, name string) (*exec.Cmd, string) {
	t.Helper()
	source, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	in, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	path := filepath.Join(dir, name)
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	// argv[0] "sleep" keeps a multi-call coreutils binary working.
	cmd := &exec.Cmd{Path: path, Args: []string{"sleep", "60"}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd, path
}

// A gateway whose file an in-place upgrade replaced while it ran, or that a
// source install moved into its custody, still runs this binary: the
// kernel shows the same path plus " (deleted)", or the custody copy. Any
// other path is not this binary.
func TestProveOwnGatewayKeepsAGatewayWhoseFileWasReplaced(t *testing.T) {
	dir := t.TempDir()
	cmd, path := startCopiedSleep(t, dir, "defenseclaw-gateway")
	pid := cmd.Process.Pid
	if _, err := proveOwnGateway(pid, path); err != nil {
		t.Fatalf("the binary itself: %v", err)
	}
	if _, err := proveOwnGateway(pid, path+"-other"); !errors.Is(err, ErrGatewayNotVerified) {
		t.Fatalf("another path: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if live, _ := processExecutable(pid); live != path+" (deleted)" {
		t.Fatalf("precondition: live executable %q", live)
	}
	if _, err := proveOwnGateway(pid, path); err != nil {
		t.Fatalf("a replaced binary: %v", err)
	}
	if _, err := proveOwnGateway(pid, filepath.Join(dir, "elsewhere")); !errors.Is(err, ErrGatewayNotVerified) {
		t.Fatalf("a replaced binary of another path: %v", err)
	}

	moved, movedPath := startCopiedSleep(t, dir, "defenseclaw-gateway-2")
	custody := filepath.Join(dir, ".defenseclaw-install-custody")
	if err := os.Mkdir(custody, 0o700); err != nil {
		t.Fatal(err)
	}
	retired := filepath.Join(custody, "retired-"+strings.Repeat("ab", 32))
	if err := os.Rename(movedPath, retired); err != nil {
		t.Fatal(err)
	}
	if _, err := proveOwnGateway(moved.Process.Pid, movedPath); err != nil {
		t.Fatalf("a binary moved into the install custody: %v", err)
	}
}
