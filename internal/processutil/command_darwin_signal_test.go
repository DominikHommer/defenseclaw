//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package processutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// darwinSignalRecorder wraps the group-signal and watchdog seams. Each group
// signal and each watchdog stop (whose last act is a kill of the group) is
// recorded with whether Wait had already reaped the leader: after that its
// PID, and so its group ID, may belong to an unrelated group.
type darwinSignalRecorder struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	signals   int
	stops     int
	afterReap []string
}

func recordDarwinSignals(t *testing.T) *darwinSignalRecorder {
	t.Helper()
	rec := &darwinSignalRecorder{}
	priorSignal, priorWatchdog := signalDarwinGroup, startDarwinWatchdog
	t.Cleanup(func() { signalDarwinGroup, startDarwinWatchdog = priorSignal, priorWatchdog })
	signalDarwinGroup = func(pgid int) error {
		rec.note("kill of group " + strconv.Itoa(pgid))
		return priorSignal(pgid)
	}
	startDarwinWatchdog = func(pgid int) (func(), error) {
		stop, err := priorWatchdog(pgid)
		if err != nil {
			return nil, err
		}
		return func() {
			rec.note("watchdog stop for group " + strconv.Itoa(pgid))
			stop()
		}, nil
	}
	return rec
}

func (r *darwinSignalRecorder) note(what string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd.ProcessState != nil {
		r.afterReap = append(r.afterReap, what)
	}
	if strings.HasPrefix(what, "watchdog") {
		r.stops++
	} else {
		r.signals++
	}
}

func (r *darwinSignalRecorder) check(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd.ProcessState == nil {
		t.Fatal("RunTree returned without reaping the leader")
	}
	if r.stops != 1 || r.signals == 0 {
		t.Fatalf("watchdog stops = %d, group signals = %d; want one stop and a group kill", r.stops, r.signals)
	}
	if len(r.afterReap) != 0 {
		t.Fatalf("signals sent after Wait reaped the leader: %v", r.afterReap)
	}
}

// The watchdog, the group kill and a late cancellation signal the group only
// while the leader is unreaped, on the normal path, on cancellation and on an
// error path (W4b2 loop round 2).
func TestDarwinTreeSignalsOnlyAnUnreapedGroup(t *testing.T) {
	t.Run("exit", func(t *testing.T) {
		rec := recordDarwinSignals(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		rec.cmd = CommandContext(ctx, "/bin/sh", "-c", "exit 0")
		if err := RunTree(rec.cmd); err != nil {
			t.Fatalf("RunTree = %v", err)
		}
		// A cancellation after RunTree returned must not signal the old group.
		if err := rec.cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) {
			t.Fatalf("late Cancel = %v, want os.ErrProcessDone", err)
		}
		rec.check(t)
	})
	t.Run("cancel", func(t *testing.T) {
		rec := recordDarwinSignals(t)
		pidFile := filepath.Join(t.TempDir(), "scanner.pid")
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		rec.cmd = CommandContext(ctx, "/bin/sh", "-c", `sleep 60 & echo $! > "$1"; wait`, "sh", pidFile)
		finished := make(chan error, 1)
		go func() { finished <- RunTree(rec.cmd) }()
		pid, err := waitDarwinChildPID(pidFile)
		cancel()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Fatal("RunTree did not finish after cancellation")
		}
		if err != nil {
			t.Fatal(err)
		}
		requireDarwinChildGone(t, pid)
		_ = rec.cmd.Cancel()
		rec.check(t)
	})
	t.Run("start gate error", func(t *testing.T) {
		rec := recordDarwinSignals(t)
		prior := releaseDarwinStartGate
		t.Cleanup(func() { releaseDarwinStartGate = prior })
		gateErr := errors.New("gate write failed")
		releaseDarwinStartGate = func(*os.File) error { return gateErr }
		rec.cmd = CommandContext(t.Context(), "/bin/sh", "-c", "exit 0")
		if err := RunTree(rec.cmd); !errors.Is(err, gateErr) {
			t.Fatalf("RunTree = %v, want the gate error", err)
		}
		rec.check(t)
	})
}

// exec.Command has no context and no Cancel; Start refuses a Cancel without a
// context, so RunTree must not add one.
func TestDarwinTreeRunsACommandWithoutContext(t *testing.T) {
	if err := RunTree(exec.Command("/bin/sh", "-c", "exit 0")); err != nil {
		t.Fatalf("RunTree(exec.Command) = %v", err)
	}
	err := RunTree(exec.Command("/bin/sh", "-c", "exit 4"))
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 4 {
		t.Fatalf("RunTree(exit 4) = %v, want exit status 4", err)
	}
}

const darwinOutputHolder = "DC_PROCESSUTIL_DARWIN_OUTPUT_HOLDER"

// TestDarwinTreeOutputHolderHelper leaves its process group and keeps the
// inherited stdout and stderr open.
func TestDarwinTreeOutputHolderHelper(t *testing.T) {
	pidFile := os.Getenv(darwinOutputHolder)
	if pidFile == "" {
		t.Skip("helper for TestDarwinTreeReportsOutputHeldPastExit")
	}
	if err := syscall.Setpgid(0, 0); err != nil {
		os.Exit(2)
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		os.Exit(2)
	}
	time.Sleep(60 * time.Second)
	os.Exit(0)
}

// A command that exits 0 while a detached helper holds its output open ends
// with exec.ErrWaitDelay, not success: callers must not take the output as a
// finished run.
func TestDarwinTreeReportsOutputHeldPastExit(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "holder.pid")
	t.Cleanup(func() {
		if pid, err := waitDarwinChildPID(pidFile); err == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	cmd := exec.Command("/bin/sh", "-c",
		`"$1" -test.run='^TestDarwinTreeOutputHolderHelper$' -test.count=1 &
n=0; while [ ! -s "$2" ] && [ $n -lt 200 ]; do sleep 0.05; n=$((n+1)); done
printf '%s\n' '{"findings":[]}'; exit 0`, "sh", os.Args[0], pidFile)
	cmd.Env = append(os.Environ(), darwinOutputHolder+"="+pidFile)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.WaitDelay = 500 * time.Millisecond
	start := time.Now()
	err := RunTree(cmd)
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("RunTree = %v, want exec.ErrWaitDelay (stdout %q)", err, stdout.String())
	}
	if stdout.String() != "{\"findings\":[]}\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("RunTree took %s", elapsed)
	}
	if _, err := waitDarwinChildPID(pidFile); err != nil {
		t.Fatal(fmt.Errorf("the detached helper never held the output: %w", err))
	}
}
