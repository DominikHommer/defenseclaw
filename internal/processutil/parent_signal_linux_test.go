//go:build linux

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
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// linuxSignalRecorder wraps the group-signal seam and records each signal
// sent once the leader was reaped: its PID, and so its group ID, may then
// belong to an unrelated group. The kernel says whether the leader is
// reaped: waitid finds no such child.
type linuxSignalRecorder struct {
	mu        sync.Mutex
	signals   int
	afterReap []int
}

func recordLinuxSignals(t *testing.T) *linuxSignalRecorder {
	t.Helper()
	rec := &linuxSignalRecorder{}
	prior := signalLinuxGroup
	t.Cleanup(func() { signalLinuxGroup = prior })
	signalLinuxGroup = func(pgid int) error {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pgid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		rec.mu.Lock()
		rec.signals++
		if errors.Is(err, unix.ECHILD) {
			rec.afterReap = append(rec.afterReap, pgid)
		}
		rec.mu.Unlock()
		return prior(pgid)
	}
	return rec
}

func (r *linuxSignalRecorder) check(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.signals == 0 {
		t.Fatal("no group kill was sent")
	}
	if len(r.afterReap) != 0 {
		t.Fatalf("group signals sent after Wait reaped the leader: %v", r.afterReap)
	}
}

// exec's context watcher can call Cancel after Wait reaped the scanner. That
// cancellation must signal nothing and return os.ErrProcessDone, on a clean
// exit, after a mid-run cancellation, and when the context ends just as the
// scanner exits (W4b2 scanner, loop round 1).
func TestRunTreeSignalsOnlyAnUnreapedGroup(t *testing.T) {
	t.Run("late cancel after exit", func(t *testing.T) {
		rec := recordLinuxSignals(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cmd := CommandContext(ctx, "/bin/sh", "-c", "exit 0")
		if err := RunTree(cmd); err != nil {
			t.Fatalf("RunTree = %v", err)
		}
		if err := cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) {
			t.Fatalf("late Cancel = %v, want os.ErrProcessDone", err)
		}
		rec.check(t)
	})
	t.Run("cancel mid-run", func(t *testing.T) {
		rec := recordLinuxSignals(t)
		pidFile := filepath.Join(t.TempDir(), "helper.pid")
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cmd := CommandContext(ctx, "/bin/sh", "-c", `sleep 60 & echo $! > "$1"; wait`, "sh", pidFile)
		finished := make(chan error, 1)
		go func() { finished <- RunTree(cmd) }()
		helper := waitLinuxPIDFile(t, pidFile)
		cancel()
		select {
		case err := <-finished:
			if err == nil {
				t.Fatal("a canceled run returned success")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("RunTree did not finish after cancellation")
		}
		for deadline := time.Now().Add(5 * time.Second); sleepRunning(helper); time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("helper %d outlived the canceled run", helper)
			}
		}
		if err := cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) {
			t.Fatalf("late Cancel = %v, want os.ErrProcessDone", err)
		}
		rec.check(t)
	})
	t.Run("context ends as the scanner exits", func(t *testing.T) {
		rec := recordLinuxSignals(t)
		for i := range 60 {
			ctx, cancel := context.WithTimeout(t.Context(), time.Duration(1+i%12)*250*time.Microsecond)
			cmd := CommandContext(ctx, "/bin/sh", "-c", "exit 0")
			_ = RunTree(cmd)
			cancel()
			if cmd.Process == nil {
				continue // the context ended before Start
			}
			if err := cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) {
				t.Fatalf("run %d: late Cancel = %v, want os.ErrProcessDone", i, err)
			}
		}
		rec.check(t)
	})
}

const linuxLeaderExitedEnv = "DC_PROCESSUTIL_LEADER_EXITED"

// TestRunTreeLeaderExitedHelper is the gateway of
// TestRunTreeGatewayDiesAfterTheScannerExits: its scanner starts a helper
// and exits; the gateway then stops before its own cleanup and waits to be
// killed.
func TestRunTreeLeaderExitedHelper(t *testing.T) {
	dir := os.Getenv(linuxLeaderExitedEnv)
	if dir == "" {
		t.Skip("gateway of TestRunTreeGatewayDiesAfterTheScannerExits")
	}
	afterLinuxLeaderExit = func() {
		_ = os.WriteFile(filepath.Join(dir, "exited"), nil, 0o600)
		time.Sleep(time.Minute)
	}
	_ = RunTree(exec.Command("/bin/sh", "-c", `sleep 60 & echo $! > "$1.tmp" && mv "$1.tmp" "$1"; exit 0`,
		"sh", filepath.Join(dir, "helper.pid")))
}

// The gateway dies after the scanner leader exited and before its cleanup
// killed the group: the watchdog, a member of that group, still ends what
// the scanner left behind (W4b2 scanner, loop round 1).
func TestRunTreeGatewayDiesAfterTheScannerExits(t *testing.T) {
	if os.Getenv(linuxLeaderExitedEnv) != "" {
		t.Skip("running as the gateway")
	}
	dir := t.TempDir()
	gateway := exec.Command(os.Args[0], "-test.run=^TestRunTreeLeaderExitedHelper$", "-test.count=1")
	gateway.Env = append(os.Environ(), linuxLeaderExitedEnv+"="+dir)
	if err := gateway.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Process.Kill(); _ = gateway.Wait() })
	helper := waitLinuxPIDFile(t, filepath.Join(dir, "helper.pid"))
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(filepath.Join(dir, "exited")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the gateway never saw its scanner exit")
		}
	}
	if !sleepRunning(helper) {
		t.Fatalf("helper %d ended before the gateway died; the test proves nothing", helper)
	}
	if err := gateway.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = gateway.Wait()
	for deadline := time.Now().Add(5 * time.Second); sleepRunning(helper); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("helper %d outlived the gateway that died after its scanner exited", helper)
		}
	}
}

func waitLinuxPIDFile(t *testing.T, path string) int {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 1 {
			t.Cleanup(func() {
				if sleepRunning(pid) {
					_ = unix.Kill(pid, unix.SIGKILL)
				}
			})
			return pid
		}
	}
	t.Fatalf("no pid in %s", path)
	return 0
}
